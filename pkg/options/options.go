package options

import (
	"container/list"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

var (
	ErrInvalidArgs = errors.New("invalid args")
)

// OptionValue API
// o = &OptionValue{}
// o.set("", val)
// o.set("path", val1, val2, .... , valN)
// o.set("path.subpath", val)
// o.set("path[N], val)
// o.set("path[key], val")
// o.set("path[N].subpath, val)
// o.set("path[key].subpath, val")
//
// o.Get has equivalent functions
// o.As will attempt an automatic conversion

type OptionValue struct {
	Value interface{}
}

// splitKeyPath splits the path up into its components
func splitKeyPath(path string) []string {

	path = strings.ReplaceAll(path, "[", ".")
	path = strings.ReplaceAll(path, "]", ".")
	parts := strings.Split(path, ".")
	return parts
}

func validateTypes(typ reflect.Type, values []interface{}) bool {
	for _, value := range values {
		if reflect.TypeOf(value) != typ {
			return false
		}
	}

	return true
}

func (o *OptionValue) setMap(index string) (*OptionValue, error) {
	var (
		ok bool
	)

	var valueMap map[string]*OptionValue
	if o.Value == nil {
		valueMap = map[string]*OptionValue{}
		o.Value = valueMap
	} else {
		if valueMap, ok = o.Value.(map[string]*OptionValue); !ok {
			return nil, xerrors.Errorf("optionvalue setleaf: existing type: %T: is not map: %w", o.Value, ErrInvalidArgs)
		}
	}

	var child *OptionValue
	if child, ok = valueMap[index]; !ok {
		child = &OptionValue{}
		valueMap[index] = child
	}

	return child, nil
}

func (o *OptionValue) setList(index int) (*OptionValue, error) {
	var (
		ok bool
	)

	var valueList []*OptionValue
	if o.Value != nil {
		if valueList, ok = o.Value.([]*OptionValue); !ok {
			return nil, xerrors.Errorf("optionvalue setleaf: existing type: %T: is not list: %w", o.Value, ErrInvalidArgs)
		}
	}

	var child *OptionValue
	if len(valueList) <= index {
		newList := make([]*OptionValue, index+1)
		if len(valueList) > 0 {
			copy(newList, valueList)
		}
		child = &OptionValue{}
		newList[index] = child
		o.Value = newList
	} else {
		child = valueList[index]
	}

	return child, nil
}

func (o *OptionValue) setLeaf(args interface{}) error {
	var (
	// err error
	)

	if args == nil {
		return nil // nothing to do
	}

	children := list.New()
	o.Value = args
	children.PushBack(o)

	for children.Len() > 0 {
		element := children.Front()
		child := element.Value.(*OptionValue)
		children.Remove(element)

		childType := reflect.TypeOf(child.Value)
		childValue := reflect.ValueOf(child.Value)

		switch childType.Kind() {
		case reflect.Array, reflect.Slice:
			// If there's no items, just set the value to nil, not an empty list
			if childValue.Len() == 0 {
				child.Value = nil
				continue
			}

			// If there's only one item, don't set it as a list, instead just set the single item
			if childValue.Len() == 1 {
				child.Value = childValue.Index(0).Interface()
				continue
			}

			// More than one item, set each in the list
			newChildrenList := make([]*OptionValue, childValue.Len())
			for i := 0; i < childValue.Len(); i++ {
				// Create a new optionvalue with its value set to the value of this list item
				// this might itself be a map, array or slice, but will be queued for further processing later
				newChild := &OptionValue{childValue.Index(i).Interface()}
				newChildrenList[i] = newChild
				children.PushBack(newChild) // Add this child to processing queue
			}
			child.Value = newChildrenList
		case reflect.Map:
			var (
				ok  bool
				err error

				childrenMap  map[string]*OptionValue
				currentChild *OptionValue
			)
			if childType.Key().Kind() != reflect.String {
				return xerrors.Errorf("optionvalue setleaf: map keys must be strings: %w", ErrInvalidArgs)
			}

			// Create a child map if it doesn't exist or can't be cast to a map[string]*OptionValue
			if childrenMap, ok = child.Value.(map[string]*OptionValue); !ok {
				childrenMap = map[string]*OptionValue{}
				child.Value = childrenMap
			}

			for _, mapKey := range childValue.MapKeys() {
				mapValue := childValue.MapIndex(mapKey)
				childKeys := splitKeyPath(mapKey.String())

				if currentChild, ok = childrenMap[childKeys[0]]; !ok {
					currentChild = &OptionValue{}
					childrenMap[childKeys[0]] = currentChild
				}

				if len(childKeys) > 1 {
					for _, childKey := range childKeys[1:] {
						// Return existing child or create it if it doesn't exist yet
						if currentChild, err = currentChild.setMap(childKey); err != nil {
							return xerrors.Errorf("optionvalue setleaf: failure: %w", err)
						}
					}
				}

				currentChild.Value = mapValue.Interface()
				children.PushBack(currentChild) // Add this child to processing queue
			}
		}
	}

	return nil
}

func (o *OptionValue) Set(path string, args ...interface{}) (err error) {
	if len(args) == 0 {
		return // nothing to do
	}

	argsType := reflect.TypeOf(args[0])
	if !validateTypes(argsType, args) {
		err := ErrInvalidArgs
		return xerrors.Errorf("optionvalue: %s args are not homogenous: %w", path, err)
	}

	var argsIface interface{}

	if len(args) == 1 {
		argsIface = args[0]
	} else {
		// This flatens the varargs into a single interface argument
		argsList := reflect.MakeSlice(reflect.SliceOf(argsType), len(args), len(args))
		for i, arg := range args {
			argsList.Index(i).Set(reflect.ValueOf(arg))
		}

		argsIface = argsList.Interface()
	}

	return o.set(path, argsIface)
}

func (o *OptionValue) set(path string, args interface{}) (err error) {

	if path == "" {
		// We are at leaf node, set leaf value
		return o.setLeaf(args)
	}

	current := o
	keys := splitKeyPath(path)
	for _, key := range keys {
		if key == "" {
			continue
		}
		if indexVal, err := strconv.Atoi(key); err == nil {
			// The index is an integer and points to a list
			if current, err = current.setList(indexVal); err != nil {
				return xerrors.Errorf("optionvalue set: failure: %w", err)
			}
		} else {
			if current, err = current.setMap(key); err != nil {
				return xerrors.Errorf("optionvalue set: failure: %w", err)
			}
		}
	}

	return current.setLeaf(args)
}

func (o *OptionValue) getMap(key string) *OptionValue {
	var (
		ok     bool
		optMap map[string]*OptionValue
		optVal *OptionValue
	)

	if o.Value == nil {
		return nil
	}

	if optMap, ok = o.Value.(map[string]*OptionValue); !ok {
		return nil
	}

	if optVal, ok = optMap[key]; !ok {
		return nil
	}

	return optVal
}

func (o *OptionValue) getList(index int) *OptionValue {
	var (
		ok      bool
		optList []*OptionValue
	)

	if o.Value == nil {
		return nil
	}

	if optList, ok = o.Value.([]*OptionValue); !ok {
		return nil
	}

	if len(optList) <= index {
		return nil
	}

	return optList[index]
}

func (o *OptionValue) GetDefault(path string, def interface{}) *OptionValue {
	if path == "" {
		return o
	}

	current := o
	keys := splitKeyPath(path)
	for _, key := range keys {
		if key == "" {
			continue
		}
		if indexVal, err := strconv.Atoi(key); err == nil {
			// The index CAN be converted to int, so its assumed that its an index whithin a list
			current = current.getList(indexVal)
		} else {
			// The index can't be converted to an int, so its assumed its the key to a map
			current = current.getMap(key)
		}

		if current == nil {
			if def == nil {
				return nil
			}
			return &OptionValue{def}
		}
	}

	return current
}

func (o *OptionValue) Get(path string) *OptionValue {
	child := o.GetDefault(path, nil)
	if child == nil {
		if log.Logger.GetLevel() <= zerolog.DebugLevel {
			log.Panic().Msgf("optionalvalue: %s get failure", path)
		}

		log.Warn().Msgf("option: %s not found", path)
	}

	return child
}

func (o *OptionValue) asMap(targetType reflect.Type, targetVal reflect.Value) bool {
	var (
		ok     bool
		optMap map[string]*OptionValue
	)

	if optMap, ok = o.Value.(map[string]*OptionValue); !ok {
		if log.Logger.GetLevel() <= zerolog.DebugLevel {
			// Usually we want to know about this error, but in production, maybe only a log message
			log.Panic().Msgf("asMap: optionvalue type: %T not map[string]*OptionValue", o.Value)
		} else {
			log.Error().Msgf("asNao: optionvalue type: %T not map[string]*OptionValue", o.Value)
		}
		return false
	}

	if len(optMap) == 0 {
		return true
	}

	log.Debug().Msgf("target type: %v", targetType)

	// XXXXXXX // TODO THIS IS WHERE YOU ARE UPTO

	//if reflectType.Key().Kind() == reflect.String

	// targetTypeElem := targetType.Elem()
	// targetValElem := targetVal.Elem()

	return false
}

func (o *OptionValue) asList(targetType reflect.Type, targetVal reflect.Value) bool {
	var (
		ok      bool
		optList []*OptionValue
	)

	if optList, ok = o.Value.([]*OptionValue); !ok {

		// Probably we stored the list of one item, just as the item itself. If we want the list back
		// we'll reconstruct it here
		optList = []*OptionValue{{o.Value}}
	}

	if len(optList) == 0 {
		return true
	}

	targetTypeElem := targetType.Elem()
	targetValElem := targetVal.Elem()

	if targetValElem.Cap() < len(optList) {
		newTargetList := reflect.MakeSlice(reflect.SliceOf(targetTypeElem.Elem()), len(optList), len(optList))
		targetVal.Elem().Set(newTargetList)
	}

	for i, opt := range optList {
		if opt == nil {
			targetValElem.Index(i).Set(reflect.Zero(targetTypeElem.Elem()))
			continue
		}

		if !reflect.TypeOf(opt.Value).AssignableTo(targetTypeElem.Elem()) {
			targetVal.Elem().Set(reflect.Zero(targetTypeElem))
			if log.Logger.GetLevel() <= zerolog.DebugLevel {
				// Usually we want to know about this error, but in production, maybe only a log message
				log.Panic().Msgf("asList: optionvalue: %d: type: %T not %v", i, opt.Value, targetTypeElem.Elem())
			} else {
				log.Error().Msgf("asList: optionvalue: %d: type: %T not %v", i, o.Value, targetTypeElem.Elem())
			}

			return false
		}

		targetValElem.Index(i).Set(reflect.ValueOf(opt.Value))
	}

	return true
}

func (o *OptionValue) As(target interface{}) bool {
	if target == nil {
		if log.Logger.GetLevel() <= zerolog.DebugLevel {
			// Usually we want to know about this error, but in production, maybe only a log message
			log.Panic().Msgf("as: target cannot be nil")
		} else {
			log.Error().Msgf("as: target cannot be nil")
		}

		return false
	}

	targetVal := reflect.ValueOf(target)
	targetType := targetVal.Type()
	if targetType.Kind() != reflect.Ptr || targetVal.IsNil() {
		if log.Logger.GetLevel() <= zerolog.DebugLevel {
			// Usually we want to know about this error, but in production, maybe only a log message
			log.Panic().Msgf("as: target must be a non-nil pointer")
		} else {
			log.Error().Msgf("as: target must be a non-nil pointer")
		}

		return false
	}

	if o == nil || o.Value == nil {
		targetVal.Elem().Set(reflect.Zero(targetVal.Elem().Type()))
		return true
	}

	targetTypeElem := targetType.Elem()
	switch targetTypeElem.Kind() {
	case reflect.Array, reflect.Slice:
		return o.asList(targetType, targetVal)
	case reflect.Map:
		return o.asMap(targetType, targetVal)
	default:
		srcVal := reflect.ValueOf(o.Value)
		targetValElem := targetVal.Elem()

		if reflect.TypeOf(o.Value).AssignableTo(targetTypeElem) {
			targetValElem.Set(srcVal)
			return true
		}

		if x, ok := o.Value.(interface{ As(interface{}) bool }); ok && x.As(target) {
			return true
		}

	}

	if log.Logger.GetLevel() <= zerolog.DebugLevel {
		// Usually we want to know about this error, but in production, maybe only a log message
		log.Panic().Msgf("failure to assign src type: %T to target type: %s", o.Value, reflect.Indirect(targetVal).Kind())
	} else {
		log.Error().Msgf("failure to assign src type: %T to target type: %s", o.Value, reflect.Indirect(targetVal).Kind())
	}

	return false
}

func (o *OptionValue) String() string {
	if x, ok := o.Value.(interface{ String() string }); ok {
		return x.String()
	}

	return fmt.Sprintf("%v", o.Value)
}

func (o *OptionValue) Bool() bool {
	var res bool
	o.As(&res)
	return res
}
