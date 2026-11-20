# shellcheck shell=bash
# The Java SDK on ligo1 (.specs/ligo-client-sdk-java.md JV-L1 to JV-L3): a JRE from apt (ligo1 reaches the internet
# through the VM's NAT), the SDK's jar and the jars it needs, built on the lab host (Maven and a JDK 17 or later),
# the Java echo client and the helper of the Go lab tests.

JAVA_DIR=/opt/ligo-java
JAVA_HOME_LAB=/usr/local/lib/ligo-lab

# java_install: builds the SDK, the echo client and the helper from this checkout and installs them on ligo1; run
# again after a change.
java_install() {
	section "The Java SDK on ligo1"
	local out="$LAB_STATE_DIR/java" jar
	command -v javac >/dev/null || die "no JDK on the lab host (a JDK 17 or later)"
	command -v jar >/dev/null || die "no jar tool on the lab host (a JDK 17 or later)"
	rm -rf "$out"
	mkdir -p "$out/lib" "$out/classes"
	(cd "$REPO_DIR/sdk/java" && ./mvnw -B -ntp -q -DskipTests package dependency:copy-dependencies \
		-DoutputDirectory="$out/lib" -DincludeScope=runtime) >"$out/build.log" 2>&1 || { tail -20 "$out/build.log" >&2; die "cannot build the Java SDK"; }
	for jar in "$REPO_DIR"/sdk/java/target/ligo-client-*.jar; do
		case "$jar" in *-sources.jar | *-javadoc.jar) ;; *) cp "$jar" "$out/lib/" ;; esac
	done
	javac --release 17 -cp "$out/lib/*" -d "$out/classes" "$REPO_DIR/test/lab/echo/client-java/EchoClient.java" \
		"$REPO_DIR/test/lab/java/SdkCheck.java" || die "cannot compile the Java lab helpers"
	jar cf "$out/lib/ligo-lab-helpers.jar" -C "$out/classes" .
	tar -C "$out" -cf "$out/lib.tar" lib
	inner_exec ligo1 sh -ec 'command -v java >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openjdk-17-jre-headless; }' \
		>/dev/null || die "cannot install a JRE on ligo1 (does it reach the apt mirrors?)"
	inner_push "$out/lib.tar" ligo1 /root/ligo-java-lib.tar 0644
	inner_exec ligo1 sh -ec "rm -rf $JAVA_DIR && mkdir -p $JAVA_DIR $JAVA_HOME_LAB && tar -C $JAVA_DIR -xf /root/ligo-java-lib.tar && chmod -R a+rX $JAVA_DIR"
	cat >"$out/echo-client-java" <<SCRIPT
#!/bin/sh
exec java -cp '$JAVA_DIR/lib/*' EchoClient "\$@"
SCRIPT
	cat >"$out/sdk-check-java" <<SCRIPT
#!/bin/sh
exec java -cp '$JAVA_DIR/lib/*' SdkCheck "\$@"
SCRIPT
	inner_push "$out/echo-client-java" ligo1 /usr/local/bin/echo-client-java 0755
	inner_push "$out/sdk-check-java" ligo1 "$JAVA_HOME_LAB/sdk-check-java" 0755
	info "ligo-client $(basename "$(ls "$out"/lib/ligo-client-*.jar | head -1)" .jar) on ligo1, $(inner_exec ligo1 java -version 2>&1 | head -1)"
}
