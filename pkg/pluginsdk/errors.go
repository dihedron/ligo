package pluginsdk

import (
	"fmt"
	"regexp"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// genericCode replaces a malformed code, and stands for errors without a
// PluginErrorDetail.
const genericCode = "PLUGIN_ERROR"

// maxPublicMessage is the limit of PluginErrorDetail.public_message, in
// characters (§5.9).
const maxPublicMessage = 512

var ligoCodeRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

// Error is a plugin error (§5.8 rule 5): a gRPC status with a
// PluginErrorDetail. ligoCode is UPPER_SNAKE_CASE; publicMessage carries no
// secrets and no SQL text, and is cut to 512 characters.
func Error(code codes.Code, ligoCode, publicMessage string, retryable bool) error {
	if !ligoCodeRE.MatchString(ligoCode) {
		ligoCode = genericCode
	}
	if r := []rune(publicMessage); len(r) > maxPublicMessage {
		publicMessage = string(r[:maxPublicMessage])
	}
	st, err := status.New(code, publicMessage).WithDetails(&pluginv2.PluginErrorDetail{
		Retryable: retryable, Code: ligoCode, PublicMessage: publicMessage,
	})
	if err != nil { // only for an invalid code: there is nothing better to return
		return status.Error(code, publicMessage)
	}
	return st.Err()
}

// ErrOwnedByOtherBinding is Ensure* finding a resource tagged with another
// binding id (§5.8 rule 2).
func ErrOwnedByOtherBinding(resource string) error {
	return Error(codes.FailedPrecondition, "RESOURCE_OWNED_BY_OTHER_BINDING",
		fmt.Sprintf("%s is owned by another binding", resource), false)
}

// FromError is the host's reading of a plugin error: its gRPC code and its
// PluginErrorDetail, the only parts the host persists. An error without a
// detail gets PLUGIN_ERROR and no message, since its text may hold anything.
func FromError(err error) (codes.Code, *pluginv2.PluginErrorDetail) {
	st := status.Convert(err)
	for _, d := range st.Details() {
		if detail, ok := d.(*pluginv2.PluginErrorDetail); ok {
			return st.Code(), detail
		}
	}
	return st.Code(), &pluginv2.PluginErrorDetail{Code: genericCode}
}
