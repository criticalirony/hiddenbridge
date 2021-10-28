package options

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
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

var splitKeyPathRE = regexp.MustCompile(`^(?:(\w+)|\[([\w\.]+)\])\.?(.*)$`)

// splitKeyPath gives us the root key and the remaining subkeys
func splitKeyPath(path string) (string, string) {

	var key string
	parts := []string{}

	key = path
	for {
		// This looping is needed to flatten possible nested keys:
		// root[nested.key.here].another.path etc.
		m := splitKeyPathRE.FindStringSubmatch(key)

		key = m[1]
		if key == "" {
			key = m[2]
		}

		if len(m[3]) == 0 {
			// No more remaining path, so the key has been flattened by this point
			break
		}

		// "fancy" prepend
		parts = append(parts, "")
		copy(parts[1:], parts)
		parts[0] = m[3]
	}

	return key, strings.Join(parts, ".")
}

func validateTypes(typ reflect.Type, values []interface{}) bool {
	for _, value := range values {
		if reflect.TypeOf(value) != typ {
			return false
		}
	}

	return true
}

func (o *OptionValue) setMap(index, path string, args interface{}) error {
	var (
		ok bool
	)

	var valueMap map[string]*OptionValue
	if o.Value == nil {
		valueMap = map[string]*OptionValue{}
		o.Value = valueMap
	} else {
		if valueMap, ok = o.Value.(map[string]*OptionValue); !ok {
			return xerrors.Errorf("optionvalue setleaf: existing type: %T: is not map: %w", o.Value, ErrInvalidArgs)
		}
	}

	var child *OptionValue
	if child, ok = valueMap[index]; !ok {
		child = &OptionValue{}
		valueMap[index] = child
	}

	return child.set(path, args)
}

func (o *OptionValue) setList(index int, path string, args interface{}) error {
	var (
		ok bool
	)

	var valueList []*OptionValue
	if o.Value != nil {
		if valueList, ok = o.Value.([]*OptionValue); !ok {
			return xerrors.Errorf("optionvalue setleaf: existing type: %T: is not list: %w", o.Value, ErrInvalidArgs)
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

	return child.set(path, args)
}

func (o *OptionValue) setLeaf(args interface{}) error {
	var (
	// argsIface interface{}
	)

	argsIfaceType := reflect.TypeOf(args)
	argsValue := reflect.ValueOf(args)
	switch argsIfaceType.Kind() {
	case reflect.Array, reflect.Slice:
		// If there's no items, nothing to do
		if argsValue.Len() == 0 {
			return nil
		}

		// If there's only one item, don't set it as a list, instead just set the single item
		if argsValue.Len() == 1 {
			if err := o.set("", argsValue.Index(0).Interface()); err != nil {
				return xerrors.Errorf("optionvalue setleaf: set: %v failure: %w", argsValue.Index(0).Interface(), err)
			}

			return nil
		}

		// More than one item, set each in the list with a "key" of its index
		for i := 0; i < argsValue.Len(); i++ {
			if err := o.set(strconv.Itoa(i), argsValue.Index(i).Interface()); err != nil {
				return xerrors.Errorf("optionvalue setleaf: set list: %d: %v failure: %w", i, argsValue.Index(i).Interface(), err)
			}
		}
	case reflect.Map:
		if argsIfaceType.Key().Kind() != reflect.String {
			return xerrors.Errorf("optionvalue setleaf: map keys must be strings: %w", ErrInvalidArgs)
		}
		for _, mapKey := range argsValue.MapKeys() {
			mapValue := argsValue.MapIndex(mapKey)
			if err := o.set(mapKey.String(), mapValue.Interface()); err != nil {
				return xerrors.Errorf("optionvalue setleaf: set map: %s: %v failure: %w", mapKey.String(), mapValue.Interface(), err)
			}
		}
	default:
		o.Value = args
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

	key, path := splitKeyPath(path)

	if indexVal, err := strconv.Atoi(key); err == nil {
		// The index is an integer and points to a list
		return o.setList(indexVal, path, args)
	}

	// The index is a string and points to a map
	return o.setMap(key, path, args)
}

func (o *OptionValue) getMap(key string, path string, def interface{}) *OptionValue {
	var (
		ok     bool
		optMap map[string]*OptionValue
		optVal *OptionValue
	)

	if o.Value == nil {
		return &OptionValue{def}
	}

	if optMap, ok = o.Value.(map[string]*OptionValue); !ok {
		return &OptionValue{def}
	}

	if optVal, ok = optMap[key]; !ok {
		return &OptionValue{def}
	}

	return optVal.GetDefault(path, def)
}

func (o *OptionValue) getList(index int, path string, def interface{}) *OptionValue {
	var (
		ok      bool
		optList []*OptionValue
	)

	if o.Value == nil {
		return &OptionValue{def}
	}

	if optList, ok = o.Value.([]*OptionValue); !ok {
		return &OptionValue{def}
	}

	if len(optList) <= index {
		return &OptionValue{def}
	}

	return optList[index].GetDefault(path, def)
}

func (o *OptionValue) GetDefault(path string, def interface{}) *OptionValue {
	if path == "" {
		return o
	}

	key, path := splitKeyPath(path)

	if indexVal, err := strconv.Atoi(key); err == nil {
		// The index is an integer and points to a list
		return o.getList(indexVal, path, def)
	}

	return o.getMap(key, path, def)
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

	XXXXXXX // TODO THIS IS WHERE YOU ARE UPTO

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
		if log.Logger.GetLevel() <= zerolog.DebugLevel {
			// Usually we want to know about this error, but in production, maybe only a log message
			log.Panic().Msgf("asList: optionvalue type: %T not []*OptionValue", o.Value)
		} else {
			log.Error().Msgf("asList: optionvalue type: %T not []*OptionValue", o.Value)
		}
		return false
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

	if o.Value == nil {
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
