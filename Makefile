include $(GOROOT)/src/Make.$(GOARCH)

TARG=github.com/devcamcar/restful
GOFILES=\
	restful.go\

include $(GOROOT)/src/Make.pkg
