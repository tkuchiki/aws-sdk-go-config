# aws-sdk-go-config

---

```go
    import "github.com/tkuchiki/aws-sdk-go-config"
```

## Usage

```go
const (
	// DefaultProfile is default profile name
	DefaultProfile = "default"
)
```

#### func  GetSharedConfigFile

```go
func GetSharedConfigFile() string
```
GetSharedConfigFile returns the path to the shared config file

#### func  GetProfile

```go
func GetProfile() string
```
GetProfile returns the profile

#### func  GetProfiles

```go
func GetProfiles(configFile ...string) []string
```
GetProfiles returns the shared config file section names

#### func  GetRegion

```go
func GetRegion() string
```
GetRegion returns the region

#### func  GetRegionFromConfigFile

```go
func GetRegionFromConfigFile(configFile, profile string) (string, error)
```
GetRegionFromConfigFile returns the region from the shared config file

#### func  GetRegionFromInstanceIdentityDocument

```go
func GetRegionFromInstanceIdentityDocument() string
```
GetRegionFromInstanceIdentityDocument returns the region from the Instance
Metadata

#### func  GetSharedCredentialsFile

```go
func GetSharedCredentialsFile() string
```
GetSharedCredentialsFile returns the path to the shared credentials file

#### func  NewConfig

```go
func NewConfig(opt Option) (*aws.Config, error)
```
NewConfig returns the *aws.Config

#### func  NewCredentials

```go
func NewCredentials(opt Option) *credentials.Credentials
```
NewCredentials returns the *credentials.Credentials

#### func  NewSession

```go
func NewSession(arg ...interface{}) (*session.Session, error)
```
NewSession returns the *session.Session.

The argument arg Option or *aws.Config

#### type Option

```go
type Option struct {
	// AWS Access Key ID
	AccessKey string
	// AWS Access Secret Access Key
	SecretKey string
	// AWS Profile
	Profile string
	// Path to the shared config file
	Config string
	// Path to the shared credentials file
	Credentials string
	// AWS Session Token
	Token string
	// AWS Region
	Region string
}
```

Option is AWS Config options
