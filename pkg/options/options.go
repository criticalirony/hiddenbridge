package options

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/xerrors"
)

type OptionValue struct {
	Value interface{}
}

// splitKeyPath gives us the root key and the remaining subkeys
func splitKeyPath(key string) (string, string) {
	idx := strings.Index(key, ".")
	if idx < 0 {
		return key, ""
	}

	return key[:idx], key[idx+1:] // Skip the leading "."
}

// splitKeyIndex gives us the index within the key, assuming its a map or list
func splitKeyIndex(key string) (string, string) {
	idx := strings.Index(key, "[")
	if idx < 0 {
		return key, ""
	}

	if !strings.HasSuffix(key, "]") {
		log.Warn().Msgf("malformed options path %s", key)
		return key, ""
	}

	return key[:idx], key[idx+1 : len(key)-1]
}

func (o *OptionValue) Set(key string, value interface{}) error {
	var err error

	// If key is empty then we set the root value
	if len(key) == 0 {
		o.Value = value
		return nil
	}

	if o.Value == nil {
		o.Value = map[string]*OptionValue{}
	}

	// keys can now be: "key", "key.subkey", key[subkey] (map), key[index] (list)
	// "key.sub1.sub2.sub3", "key[subkey].sub2.sub3", key.sub1[sub2].sub3[index]
	key, path := splitKeyPath(key)

	keyIndex := -1
	key, rawIndex := splitKeyIndex(key)
	if len(rawIndex) > 0 {
		if keyIndex, err = strconv.Atoi(rawIndex); err != nil {
			keyIndex = -1
		}
	}

	childMap, ok := o.Value.(map[string]*OptionValue)
	if !ok {
		return xerrors.Errorf("%s key type %T is immutable can not reassign", key, o.Value)
	}

	var child *OptionValue

	child, ok = childMap[key]
	if !ok {
		child = &OptionValue{}
		o.Value.(map[string]*OptionValue)[key] = child
	}

	if keyIndex >= 0 {
		childList, ok := child.Value.([]OptionValue)
		if !ok {
			childList = make([]OptionValue, keyIndex+1)
		} else if keyIndex >= len(childList) {
			childList = append(childList, make([]OptionValue, (keyIndex+1)-len(childList))...)
		}

		child.Value = childList
		child = &childList[keyIndex]
	}

	return child.Set(path, value)
}

func (o *OptionValue) Get(key string) *OptionValue {
	var err error

	if len(key) == 0 {
		return o
	}

	// keys can now be: "key", "key.subkey", key[subkey] (map), key[index] (list)
	// "key.sub1.sub2.sub3", "key[subkey].sub2.sub3", key.sub1[sub2].sub3[index]
	key, path := splitKeyPath(key)

	keyIndex := -1
	key, rawIndex := splitKeyIndex(key)
	if len(rawIndex) > 0 {
		if keyIndex, err = strconv.Atoi(rawIndex); err != nil {
			keyIndex = -1
		}
	}

	if o.Value == nil {
		log.Warn().Str("key", key).Msg("key has not been assigned")
		return nil
	}

	childMap, ok := o.Value.(map[string]*OptionValue)
	if !ok {
		log.Warn().Str("key", key).Str("type", fmt.Sprintf("%T", o.Value)).Msg("immutable type can not reassign")
		return nil
	}

	var child *OptionValue

	child, ok = childMap[key]
	if !ok {
		log.Warn().Str("key", key).Msg("key not found")
		return nil
	}

	if keyIndex >= 0 {
		childList, ok := child.Value.([]OptionValue)
		if !ok {
			log.Warn().Str("key", key).Msg("key not subscriptble")
			return nil
		} else if keyIndex >= len(childList) {
			log.Warn().Str("key", key).Str("index", fmt.Sprintf("%d", keyIndex)).Msg("key index out of range")
			return nil
		}

		child = &childList[keyIndex]
	}

	return child.Get(path)
}

func (o *OptionValue) Int() int {
	return o.Value.(int)
}

func (o *OptionValue) Int64() int64 {
	val, ok := o.Value.(int64)
	if !ok {
		return int64(o.Value.(int))
	}

	return val
}

func (o *OptionValue) String() string {
	val, ok := o.Value.(string)
	if !ok {
		val = fmt.Sprintf("%v", o.Value)
	}

	return val
}

func (o *OptionValue) Duration() time.Duration {
	if val, ok := o.Value.(time.Duration); ok {
		return val
	}

	if val, ok := o.Value.(string); ok {
		if dur, err := time.ParseDuration(val); err == nil {
			return dur
		}

		return 0
	}

	if val, ok := o.Value.(int); ok {
		return time.Duration(val)
	}

	if val, ok := o.Value.(int64); ok {
		return time.Duration(val)
	}

	return 0
}

func (o *OptionValue) List() []OptionValue {
	if val, ok := o.Value.([]OptionValue); ok {
		return val
	}

	if val, ok := o.Value.(map[string]OptionValue); ok {
		if len(val) == 0 {
			return []OptionValue{}
		}

		keys := make([]string, len(val))
		i := 0
		for key, _ := range val {
			keys[i] = key
			i += 1
		}

		if _, err := strconv.Atoi(keys[0]); err == nil {
			sort.Slice(keys, func(i, j int) bool {
				ii, err := strconv.Atoi(keys[i])
				if err != nil {
					return false
				}

				ji, err := strconv.Atoi(keys[j])
				if err != nil {
					return false
				}

				return ii < ji
			})
		}

		values := make([]OptionValue, len(val))
		for i, key := range keys {
			values[i] = val[key]
		}
		return values
	}

	return []OptionValue{*o} // Return self as a 1 item list
}

func (o *OptionValue) Map() map[string]OptionValue {
	if val, ok := o.Value.(map[string]OptionValue); ok {
		return val
	}

	if val, ok := o.Value.([]OptionValue); ok {
		if len(val) == 0 {
			return map[string]OptionValue{}
		}

		values := make(map[string]OptionValue, len(val))
		for i, item := range val {
			key := fmt.Sprintf("item%d", i)
			values[key] = item
		}

		return values
	}

	return map[string]OptionValue{
		"default": *o,
	} // Return self as a 1 item map with key "default"
}
