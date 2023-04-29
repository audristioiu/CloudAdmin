package main

import "cloudadmin/service"

func main() {
	s := service.NewService()
	s.StartWebService()
}
