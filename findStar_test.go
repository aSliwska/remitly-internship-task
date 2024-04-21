package main

import (
	"reflect"
	"testing"

	"github.com/Jeffail/gabs/v2"
)

func Test_IsAsteriskFree(t *testing.T) {
	type args struct {
		jsonString string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Empty PolicyDocument has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument with an empty object Statement has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": {}
					}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument with an empty array Statement has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": []
					}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument with an array Statement has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [
							{
								"Resource": "arn:aws:s3:::example_bucket"
							}
						]
					}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument with an array Statement has an asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [
							{
								"Resource": "arn:aws:s3:::example_bucket/*"
							}
						]
					}
				}`,
			},
			want: false,
		},
		{
			name: "PolicyDocument with an object Statement has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": {
							"Resource": "arn:aws:s3:::example_bucket"
						}
					}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument with an object Statement has an asterisk",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": {
							"Resource": "arn:aws:s3:::example_bucket/*"
						}
					}
				}`,
			},
			want: false,
		},
		{
			name: "PolicyDocument general example has no asterisks",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [
							{
								"Sid": "IamListAccess",
								"Effect": "Allow",
								"Action": [
									"iam:ListRoles",
									"iam:ListUsers"
								],
								"Resource": [
									"arn:aws:s3:::confidential-data"
								]
							},
							{
								"Sid": "IamListAccess",
								"Effect": "Allow",
								"Action": [
									"iam:ListRoles",
									"iam:ListUsers"
								],
								"Resource": [
									"arn:aws:s3:::confidential-data",
									"arn:aws:s3:::confidential-data"
								]
							}
						]
					}
				}`,
			},
			want: true,
		},
		{
			name: "PolicyDocument general example has an asterisk",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Version": "2012-10-17",
						"Statement": [
							{
								"Sid": "IamListAccess",
								"Effect": "Allow",
								"Action": [
									"iam:ListRoles",
									"iam:ListUsers"
								],
								"Resource": [
									"arn:aws:s3:::confidential-data"
								]
							},
							{
								"Sid": "IamListAccess",
								"Effect": "Allow",
								"Action": [
									"iam:ListRoles",
									"iam:ListUsers"
								],
								"Resource": [
									"arn:aws:s3::*:confidential-data",
									"arn:aws:s3:::confidential-data"
								]
							}
						]
					}
				}`,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAsteriskFree(tt.args.jsonString); got != tt.want {
				t.Errorf("isAsteriskFree() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPanic_IsAsteriskFree(t *testing.T) {
	type args struct {
		jsonString string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Passing a PolicyDocument with a non-object and non-array Statement causes panic",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Statement" : 4
					}
				}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { _ = recover() }()
			IsAsteriskFree(tt.args.jsonString)
			t.Errorf("Passing a PolicyDocument with a non-object and non-array Statement didn't cause panic.")
		})
	}
}

func Test_statementHasAsterisk(t *testing.T) {
	type args struct {
		statement *gabs.Container
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Statement without Resource has no asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Effect": "Allow",
					"Action": "s3:ListBucket"
				}`),
			},
			want: false,
		},
		{
			name: "Empty Statement has no asterisk",
			args: args{
				statement: parseJSONForTests(`{}`),
			},
			want: false,
		},
		{
			name: "Statement with an object Resource has no asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Effect": "Allow",
					"Resource": "arn:aws:s3:::example_bucket"
				}`),
			},
			want: false,
		},
		{
			name: "Statement with an object Resource has an asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Effect": "Allow",
					"Resource": "arn:aws:s3:::example_bucket/*"
				}`),
			},
			want: true,
		},
		{
			name: "Statement with an array Resource has no asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Sid": "IamListAccess",
					"Resource": [
						"arn:aws:s3:::confidential-data",
						"arn:aws:s3:::confidential-data"
					]
				}`),
			},
			want: false,
		},
		{
			name: "Statement with an array Resource has an asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Sid": "IamListAccess",
					"Resource": [
						"arn:aws:s3:::confidential-data",
						"arn:aws:s3:::confidential-data/*",
						"arn:aws:s3:::confidential-data"
					]
				}`),
			},
			want: true,
		},
		{
			name: "Statement with an empty array Resource has no asterisk",
			args: args{
				statement: parseJSONForTests(`{
					"Sid": "IamListAccess",
					"Resource": []
				}`),
			},
			want: false,
		},
		{
			name: "Nil Statement has no asterisk",
			args: args{
				statement: nil,
			},
			want: false,
		},
		{
			name: "Statement that is an empty gabs container has no asterisk",
			args: args{
				statement: gabs.New(),
			},
			want: false,
		},
		{
			name: "Statement that isn't an object has no asterisk",
			args: args{
				statement: gabs.Wrap(4),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statementHasAsterisk(tt.args.statement); got != tt.want {
				t.Errorf("statementHasAsterisk() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPanic_statementHasAsterisk(t *testing.T) {
	type args struct {
		statement *gabs.Container
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Passing a Statement with a non-string and non-array Resource causes panic",
			args: args{
				statement: parseJSONForTests(`{ 
					"Resource": 4 
				}`),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { _ = recover() }()
			statementHasAsterisk(tt.args.statement)
			t.Errorf("Passing a Statement with a non-string and non-array Resource didn't cause panic.")
		})
	}
}

func Test_resourceHasAsterisk(t *testing.T) {
	type args struct {
		resource *gabs.Container
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Resource has an asterisk at the end",
			args: args{
				resource: gabs.Wrap(`arn:aws:s3:::example_bucket/*`),
			},
			want: true,
		},
		{
			name: "Resource has asterisks in the middle",
			args: args{
				resource: gabs.Wrap(`arn:aws:s3*:::*example_bucket`),
			},
			want: true,
		},
		{
			name: "Resource has an asterisk at the beginning",
			args: args{
				resource: gabs.Wrap(`*arn:aws:s3:::example_bucket`),
			},
			want: true,
		},
		{
			name: "Resource has an asterisk as the only character",
			args: args{
				resource: gabs.Wrap(`*`),
			},
			want: true,
		},
		{
			name: "Resource doesn't have an asterisk",
			args: args{
				resource: gabs.Wrap(`arn:aws:s3:::example_bucket`),
			},
			want: false,
		},
		{
			name: "Empty Resource doesn't have an asterisk",
			args: args{
				resource: gabs.Wrap(``),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resourceHasAsterisk(tt.args.resource); got != tt.want {
				t.Errorf("resourceHasAsterisk() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPanic_resourceHasAsterisk(t *testing.T) {
	type args struct {
		resource *gabs.Container
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Passing an integer causes panic",
			args: args{
				resource: gabs.Wrap(4),
			},
		},
		{
			name: "Passing an JSON array with a string causes panic",
			args: args{
				resource: parseJSONForTests(`["bad input"]`),
			},
		},
		{
			name: "Passing empty gabs container causes panic",
			args: args{
				resource: gabs.New(),
			},
		},
		{
			name: "Passing a nil causes panic",
			args: args{
				resource: nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { _ = recover() }()
			resourceHasAsterisk(tt.args.resource)
			t.Errorf("Passing a resource value that isn't a string didn't cause panic.")
		})
	}
}

func Test_parseJSON(t *testing.T) {
	jsonString := `{
		"PolicyName": "root",
		"PolicyDocument": {
			"Statement": [
				{
					"Sid": "IamListAccess",
					"Resource": [
						"arn:aws:s3:::confidential-data"
					]
				},
				{
					"Resource": [
						"arn:aws:s3::*:confidential-data",
						"arn:aws:s3:::confidential-data"
					]
				}
			]
		}
	}`
	jsonStringWithEmptyValues := `{
		"PolicyName": "root",
		"PolicyDocument": {
			"Version": "2012-10-17",
			"Statement": [
				{
					"Action": [
						"",
						"iam:ListUsers"
					],
					"Resource": []
				},
				{}
			]
		}
	}`
	jsonEmptyString := `{}`

	type args struct {
		jsonString string
	}
	tests := []struct {
		name string
		args args
		want *gabs.Container
	}{
		{
			name: "Parsing JSON",
			args: args{
				jsonString: jsonString,
			},
			want: parseJSONForTests(jsonString),
		},
		{
			name: "Parsing JSON with empty values",
			args: args{
				jsonString: jsonStringWithEmptyValues,
			},
			want: parseJSONForTests(jsonStringWithEmptyValues),
		},
		{
			name: "Parsing empty JSON",
			args: args{
				jsonString: jsonEmptyString,
			},
			want: parseJSONForTests(jsonEmptyString),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseJSON(tt.args.jsonString); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPanic_parseJSON(t *testing.T) {
	type args struct {
		jsonString string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Parsing JSON with a missing value causes panic",
			args: args{
				jsonString: `{
					"PolicyName": "root",
					"PolicyDocument": {
						"Statement": [
							{
								"Sid": "IamListAccess",
								"Resource":
							}
						]
					}
				}`,
			},
		},
		{
			name: "Parsing empty JSON causes panic",
			args: args{
				jsonString: ``,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() { _ = recover() }()
			parseJSON(tt.args.jsonString)
			t.Errorf("Parsing bad JSON didn't cause panic.")
		})
	}
}

func parseJSONForTests(jsonString string) *gabs.Container {
	parsedJson, err := gabs.ParseJSON([]byte(jsonString))
	if err != nil {
		panic(err)
	}
	return parsedJson
}
