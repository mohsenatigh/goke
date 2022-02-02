package objectmodel

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/mohsenatigh/goke/gcrypto"
	"gopkg.in/go-playground/validator.v8"
)

//---------------------------------------------------------------------------------------
func parsePortRange(in string) (int, int, error) {

	parts := strings.Split(in, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("invalid port range")
	}

	part1, err := strconv.Atoi(parts[0])
	if err != nil || part1 > 65535 {
		return 0, 0, errors.New("invalid port range start value")
	}

	part2, err := strconv.Atoi(parts[1])
	if err != nil || part2 > 65535 || part1 > part2 {
		return 0, 0, errors.New("invalid port range end value")
	}

	return part1, part2, nil
}

//---------------------------------------------------------------------------------------
func ValidateObject(input interface{}) error {

	//translate error
	translateError := func(err error) error {
		//
		var re = regexp.MustCompile(`(?m)json:"(.*?)"`)
		errF := err.(validator.ValidationErrors)

		//Try to find the related JSON field
		for _, v := range errF {
			errString := ""
			names := strings.Split(v.NameNamespace, ".")
			typeOf := reflect.TypeOf(input)
			fObj, _ := typeOf.FieldByName(names[0])
			for _, n := range names[1:] {
				fObj, _ = fObj.Type.FieldByName(n)
			}
			out := re.FindAllStringSubmatch(string(fObj.Tag), 1)
			if len(out) > 0 {
				errString = fmt.Sprintf("invalid value for %s ", out[0][1])
			} else {
				errString = fmt.Sprintf("invalid value for %s ", v.NameNamespace)
			}
			return errors.New(errString)
		}
		return nil
	}

	//IP list validator
	addressListValidator := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		const maxIPAddress = 32
		list, valid := field.Interface().([]string)
		if !valid {
			return false
		}

		if len(list) > maxIPAddress {
			return false
		}

		for _, ipVal := range list {
			if ip := net.ParseIP(ipVal); ip == nil {
				return false
			}
		}
		return true
	}

	//IP range validator
	ipRangeValidator := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		addressRange, valid := field.Interface().(string)
		if !valid {
			return false
		}

		items := strings.Split(addressRange, "-")
		if len(items) != 2 {
			return false
		}

		sIp := net.ParseIP(items[0])
		dIp := net.ParseIP(items[1])

		if sIp == nil || dIp == nil {
			return false
		}

		sV4 := (sIp.To4() == nil)
		dV4 := (dIp.To4() == nil)

		return sV4 == dV4
	}

	//name validation
	isValidName := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		name, valid := field.Interface().(string)
		if !valid {
			return false
		}

		if l := len(name); l < 3 || l > 64 {
			return false
		}

		if strings.ContainsAny(name, "*^~|%><[]\"'") {
			return false
		}

		return true
	}

	//time validation
	isValidTime := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		time, valid := field.Interface().(string)
		if !valid {
			return false
		}
		re := regexp.MustCompile(`(?m)[0-2][0-9]:[0-9][0-9]`)
		return re.Match([]byte(time))
	}

	//day validation
	isValidDay := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		day, valid := field.Interface().(string)
		if !valid {
			return false
		}
		re := regexp.MustCompile(`(?m)^(mo|tu|we|th|fr|sa|su)$`)
		return re.Match([]byte(day))
	}

	//port range validation
	portRange := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		portValue, valid := field.Interface().(string)
		if !valid {
			return false
		}

		if _, _, err := parsePortRange(portValue); err != nil {
			return false
		}

		return true
	}

	//fileName validation
	fileName := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		fileNameStr, valid := field.Interface().(string)
		if !valid {
			return false
		}
		l := len(fileNameStr)
		if l > 1024 || l < 4 {
			return false
		}
		return true
	}

	//ike algorithm validator
	algorithm := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		alg, valid := field.Interface().(string)
		if !valid {
			return false
		}
		if _, err := gcrypto.ParseAlgorithm(alg); err != nil {
			return false
		}

		return true
	}

	//port address validator
	portAddress := func(v *validator.Validate, topStruct reflect.Value, currentStruct reflect.Value, field reflect.Value, fieldtype reflect.Type, fieldKind reflect.Kind, param string) bool {
		portVal, valid := field.Interface().(int)
		if !valid || portVal < 1 || portVal > 0xffff {
			return false
		}

		return true
	}

	//validate
	config := &validator.Config{TagName: "validate"}
	validate := validator.New(config)
	validate.RegisterValidation("iplist", addressListValidator)
	validate.RegisterValidation("iprange", ipRangeValidator)
	validate.RegisterValidation("port", portAddress)
	validate.RegisterValidation("name", isValidName)
	validate.RegisterValidation("time", isValidTime)
	validate.RegisterValidation("day", isValidDay)
	validate.RegisterValidation("port_range", portRange)
	validate.RegisterValidation("file", fileName)
	validate.RegisterValidation("algorithm", algorithm)

	//
	err := validate.Struct(input)
	if err != nil {
		return translateError(err)
	}
	return nil
}
