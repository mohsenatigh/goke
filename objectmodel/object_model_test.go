package objectmodel

import (
	"testing"
)

type TestStruct struct {
	IpList        []string `validate:"omitempty,iplist"`
	IpListInt     []int    `validate:"omitempty,iplist"`
	IpRange       string   `validate:"omitempty,iprange"`
	Port          int      `validate:"omitempty,port"`
	Name          string   `validate:"omitempty,name"`
	Time          string   `validate:"omitempty,time"`
	Day           string   `validate:"omitempty,day"`
	PortRange     string   `validate:"omitempty,port_range"`
	File          string   `validate:"omitempty,file"`
	Algorithm     string   `validate:"omitempty,algorithm"`
	AlgorithmJson string   `json:"algorithm" validate:"omitempty,algorithm"`
}

func TestObjectModelFunctionality(t *testing.T) {

	type testCase struct {
		testdata TestStruct
		result   bool
	}

	//create test cases
	testCases := []testCase{
		//test ip list
		{
			TestStruct{
				IpList: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			},
			true,
		},
		{
			TestStruct{
				IpList: []string{"test"},
			},
			false,
		},
		{
			TestStruct{
				IpListInt: []int{0},
			},
			false,
		},
		//test ip range
		{
			TestStruct{
				IpRange: "192.168.1.1-192.168.1.2",
			},
			true,
		},
		{
			TestStruct{
				IpRange: "192.168.1.1",
			},
			false,
		},
		{
			TestStruct{
				IpRange: "192.168.1.1-::01",
			},
			false,
		},
		//test port
		{
			TestStruct{
				Port: 64,
			},
			true,
		},
		{
			TestStruct{
				Port: 0xffffff,
			},
			false,
		},
		//test name
		{
			TestStruct{
				Name: "name",
			},
			true,
		},
		//test day
		{
			TestStruct{
				Day: "mo",
			},
			true,
		},
		//test port_range
		{
			TestStruct{
				PortRange: "100:256",
			},
			true,
		},
		{
			TestStruct{
				PortRange: "0:999999",
			},
			false,
		},
		{
			TestStruct{
				PortRange: "100",
			},
			false,
		},
		{
			TestStruct{
				PortRange: "100:50",
			},
			false,
		},
		{
			TestStruct{
				PortRange: "1000000:50",
			},
			false,
		},

		//test time
		{
			TestStruct{
				Time: "19:22",
			},
			true,
		},

		//test file
		{
			TestStruct{
				File: "c:\\test.txt",
			},
			true,
		},

		//test algorithm
		{
			TestStruct{
				Algorithm: "enc:aes-128,auth:hmac_sha2_256_128,prf:hmac_sha2_256,dh:group20",
			},
			true,
		},

		//test json parsing
		{
			TestStruct{
				AlgorithmJson: "invalid",
			},
			false,
		},
	}

	//test
	for _, c := range testCases {
		if err := ValidateObject(c.testdata); (err == nil) != c.result {
			t.FailNow()
		}
	}

}
