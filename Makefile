include $(GOROOT)/src/Make.$(GOARCH)

TARG=restful
GOFILES=\
	restful.go\

include $(GOROOT)/src/Make.pkg
