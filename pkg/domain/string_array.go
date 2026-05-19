package domain

import "encoding/json"

type StringArray []string

var _ json.Marshaler = (*StringArray)(nil)
var _ json.Unmarshaler = (*StringArray)(nil)

func (j *StringArray) MarshalJSON() ([]byte, error) {
	array := make([]string, len(*j))
	copy(array, *j)

	if len(array) == 1 {
		return json.Marshal(array[0])
	} else {
		return json.Marshal(array)
	}
}

func (j *StringArray) UnmarshalJSON(data []byte) error {
	var array []string
	if err := json.Unmarshal(data, &array); err != nil {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		*j = StringArray{str}
		return nil
	}

	*j = StringArray(array)
	return nil
}
