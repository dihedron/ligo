# SPDX-License-Identifier: MIT
# The Java SDK's targets, included by the Makefile.

# The Java SDK (sdk/java) builds with the Maven wrapper checked in beside it, on
# a JDK 17 or later. A release is built at the tag's version (-Drevision);
# without a tag the jars are 0.0.0-SNAPSHOT.
JAVA_VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//')
JAVA_REVISION = $(if $(JAVA_VERSION),-Drevision=$(JAVA_VERSION),)

.PHONY: java-test
java-test: ## run the Java SDK's tests (JDK 17 or later)
	@cd sdk/java && ./mvnw -B -ntp test

.PHONY: java-lint
java-lint: ## check the Java SDK: dependency convergence, SpotBugs, javadoc (the tests are java-test)
	@cd sdk/java && ./mvnw -B -ntp -DskipTests verify

.PHONY: java-build
java-build: ## build the Java SDK's jar, sources jar, javadoc jar and pom into build/java (version from the git tag)
	@rm -rf build/java && mkdir -p build/java
	@cd sdk/java && ./mvnw -B -ntp -DskipTests $(JAVA_REVISION) package
	@cp sdk/java/target/ligo-client-*.jar build/java/
	@sed 's|$${revision}|$(or $(JAVA_VERSION),0.0.0-SNAPSHOT)|' sdk/java/pom.xml > build/java/ligo-client-$(or $(JAVA_VERSION),0.0.0-SNAPSHOT).pom

.PHONY: java-bench
java-bench: ## run the Java SDK's JMH benchmark of bindings answered 304
	@cd sdk/java && ./mvnw -B -ntp -q -Pbench test-compile exec:exec
