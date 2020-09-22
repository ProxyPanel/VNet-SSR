package arrayx

import (
	"reflect"
)

func FindStringInArray(obj string, target []string) bool {
	for _, item := range target {
		if obj == item {
			return true
		}
	}
	return false
}

func In(obj interface{}, collections interface{}) bool {
	refCollections := reflect.ValueOf(collections)
	refObj := reflect.ValueOf(obj)
	if refCollections.Kind() != reflect.Slice {
		return false
	}

	for i := 0; i < refCollections.Len(); i++ {
		items := refCollections.Index(i)
		if items.Kind() != refObj.Kind() {
			return false
		}

		switch items.Kind() {
		case reflect.String:
			if items.String() == refObj.String() {
				return true
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if items.Int() == refObj.Int() {
				return true
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if items.Uint() == refObj.Uint() {
				return true
			}
		}
	}

	return false

}
