package domain

import (
	"encoding/json"
	"testing"
)

type Data struct {
	Property StringArray `json:"property"`
}

type DataWithIgnore struct {
	Property *StringArray `json:"property,omitempty"`
}

func Test_Unmarshall_One(t *testing.T) {
	text := `{"property":"value"}`
	data := &Data{}
	err := json.Unmarshal([]byte(text), data)
	if err != nil {
		t.Error(err)
	}

	if len(data.Property) != 1 {
		t.Error("expected 1 element in the array")
	}

	if data.Property[0] != "value" {
		t.Error("unexpected value")
	}
}

func Test_Unmarshall_Many(t *testing.T) {
	text := `{"property":["value1","value2"]}`
	data := &Data{}
	err := json.Unmarshal([]byte(text), data)
	if err != nil {
		t.Error(err)
	}

	if len(data.Property) != 2 {
		t.Error("expected 2 elements in the array")
	}

	if data.Property[0] != "value1" {
		t.Error("unexpected value")
	}

	if data.Property[1] != "value2" {
		t.Error("unexpected value")
	}
}

func Test_Marshall_One(t *testing.T) {
	data := &Data{
		Property: StringArray{"value"},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":"value"}` {
		t.Error("unexpected json")
	}
}

func Test_Marshall_Many(t *testing.T) {
	data := &Data{
		Property: StringArray{"value1", "value2"},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":["value1","value2"]}` {
		t.Error("unexpected json")
	}
}

func Test_Marshall_Empty(t *testing.T) {
	data := &Data{
		Property: StringArray{},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":[]}` {
		t.Error("unexpected json")
	}
}

func Test_Unmarshall_Pointer_One(t *testing.T) {
	text := `{"property":"value"}`
	data := &DataWithIgnore{}
	err := json.Unmarshal([]byte(text), data)
	if err != nil {
		t.Error(err)
	}

	if len(*data.Property) != 1 {
		t.Error("expected 1 element in the array")
	}

	if (*data.Property)[0] != "value" {
		t.Error("unexpected value")
	}
}

func Test_Unmarshall_Pointer_Many(t *testing.T) {
	text := `{"property":["value1","value2"]}`
	data := &DataWithIgnore{}
	err := json.Unmarshal([]byte(text), data)
	if err != nil {
		t.Error(err)
	}

	if len(*data.Property) != 2 {
		t.Error("expected 2 elements in the array")
	}

	if (*data.Property)[0] != "value1" {
		t.Error("unexpected value")
	}

	if (*data.Property)[1] != "value2" {
		t.Error("unexpected value")
	}
}

func Test_Marshall_Pointer_Null(t *testing.T) {
	data := &DataWithIgnore{
		Property: nil,
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{}` {
		t.Error("unexpected json")
	}
}

func Test_Marshall_Pointer_One(t *testing.T) {
	data := &DataWithIgnore{
		Property: &StringArray{"value"},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":"value"}` {
		t.Error("unexpected json")
	}
}

func Test_Marshall_Pointer_Many(t *testing.T) {
	data := &DataWithIgnore{
		Property: &StringArray{"value1", "value2"},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":["value1","value2"]}` {
		t.Error("unexpected json")
	}
}

func Test_Marshall_Pointer_Empty(t *testing.T) {
	data := &DataWithIgnore{
		Property: &StringArray{},
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Error(err)
	}

	if string(b) != `{"property":[]}` {
		t.Error("unexpected json")
	}
}

func Test_Unmarshall_Pointer_Null(t *testing.T) {
	text := `{"property":null}`
	data := &DataWithIgnore{}
	err := json.Unmarshal([]byte(text), data)
	if err != nil {
		t.Error(err)
	}

	if data.Property != nil {
		t.Error("expected nil")
	}
}
