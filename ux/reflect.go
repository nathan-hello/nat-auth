package ux

import (
	"errors"
	"fmt"
	"reflect"
)

func GetUserFields(user interface{}) (User, error) {
	v := reflect.ValueOf(user)

	// Ensure the provided user is a pointer to a struct
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return User{}, errors.New("provided value is not a struct or pointer to a struct")
	}

	// Fetch the fields by their names
	id, err := getFieldAsString(v, "ID")
	if err != nil {
		return User{}, err
	}

	email, err := getFieldAsString(v, "Email")
	if err != nil {
		return User{}, err
	}

	username, err := getFieldAsString(v, "Username")
	if err != nil {
		return User{}, err
	}

	encryptedPassword, err := getFieldAsString(v, "EncryptedPassword")
	if err != nil {
		return User{}, err
	}

	passwordSalt, err := getFieldAsString(v, "PasswordSalt")
	if err != nil {
		return User{}, err
	}

	return User{
		ID:                id,
		Email:             email,
		Username:          username,
		EncryptedPassword: encryptedPassword,
		PasswordSalt:      passwordSalt,
	}, nil
}

func getFieldAsString(v reflect.Value, fieldName string) (string, error) {
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return "", fmt.Errorf("field %s does not exist", fieldName)
	}

	if field.Kind() != reflect.String {
		return "", fmt.Errorf("field %s is not a string", fieldName)
	}

	return field.String(), nil
}
