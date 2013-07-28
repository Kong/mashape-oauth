#
# Run all tests
#
test:
	@@node_modules/.bin/mocha -R spec tests/*

.PHONY: test install