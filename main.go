package main

import "fmt"

func main() {
	fmt.Println(IsAsteriskFree(`{
		"PolicyName": "root",
		"PolicyDocument": {
			"Version": "2012-10-17",
			"Statement": {
				"Effect": "Allow",
				"Action": "s3:ListBucket",
				"Resource": "arn:aws:s3:::example_bucket"
			}
		}
	}
	`))
}
