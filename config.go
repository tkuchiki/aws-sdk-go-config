package awsconfig

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/mitchellh/go-homedir"
	"gopkg.in/ini.v1"
	"os"
	"path/filepath"
)

// Option is AWS Config options
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

const (
	// DefaultProfile is default profile name
	DefaultProfile = "default"
)

func loadIni(filename string) (*ini.File, error) {
	return ini.Load(filename)
}

// GetRegionFromConfigFile returns the region from the shared config file
func GetRegionFromConfigFile(configFile, profile string) (string, error) {
	var cfg *ini.File
	var err error
	cfg, err = loadIni(configFile)

	if err != nil {
		return "", err
	}

	var s *ini.Section
	s, err = cfg.GetSection(profile)
	if err != nil {
		return "", err
	}

	var key *ini.Key
	key, err = s.GetKey("region")

	return key.String(), err
}

// GetProfiles returns the shared config file section names
func GetProfiles(configFile ...string) []string {
	var cfg *ini.File
	var err error
	var conf string

	if len(configFile) == 0 {
		conf = GetSharedCredentialsFile()
	} else {
		conf = configFile[0]
	}

	cfg, err = loadIni(conf)

	if err != nil {
		return []string{}
	}

	defaultSectionLen := len(cfg.Section("").Keys())
	sections := cfg.SectionStrings()

	if defaultSectionLen == 0 {
		return sections[1:]
	}

	return sections
}

// GetProfile returns the profile
func GetProfile() string {
	var profile string
	if os.Getenv("AWS_SDK_LOAD_CONFIG") == "1" {
		profile = os.Getenv("AWS_DEFAULT_PROFILE")
	} else {
		profile = os.Getenv("AWS_PROFILE")
	}

	if profile == "" {
		return DefaultProfile
	}

	return profile
}

// GetRegionFromInstanceIdentityDocument returns the region from the Instance Metadata
func GetRegionFromInstanceIdentityDocument() string {
	region, err := ec2metadata.New(session.New()).Region()
	if err == nil {
		return region
	}

	return ""
}

// GetRegion returns the region
func GetRegion() string {
	var region string
	if os.Getenv("AWS_SDK_LOAD_CONFIG") == "1" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	} else {
		region = os.Getenv("AWS_REGION")
	}

	if region == "" {
		region, _ = GetRegionFromConfigFile(GetSharedConfigFile(), DefaultProfile)
	}

	if region == "" && os.Getenv("USE_METADATA") != "0" {
		region = GetRegionFromInstanceIdentityDocument()
	}

	return region
}

func createConfigPath(filename string) string {
	dir, err := homedir.Dir()
	if err != nil {
		return ""
	}

	// /path/to/homedir/.aws/{config,credentials}
	return filepath.Join(dir, ".aws", filename)
}

// GetSharedCredentialsFile returns the path to the shared credentials file
func GetSharedCredentialsFile() string {
	var creds string
	creds = os.Getenv("AWS_SHARED_CREDENTIALS_FILE")

	if creds == "" {
		creds = createConfigPath("credentials")
	}

	return creds
}

// GetSharedConfigFile returns the path to the shared config file
func GetSharedConfigFile() string {
	var config string
	config = os.Getenv("AWS_CONFIG_FILE")

	if config == "" {
		config = createConfigPath("config")
	}

	return config
}

// NewCredentials returns the *credentials.Credentials
func NewCredentials(opt Option) *credentials.Credentials {
	var creds *credentials.Credentials
	var profile string

	if opt.Profile == "" {
		profile = GetProfile()
	} else {
		profile = opt.Profile
	}

	if opt.AccessKey != "" && opt.SecretKey != "" {
		creds = credentials.NewStaticCredentials(opt.AccessKey, opt.SecretKey, opt.Token)
	} else {
		creds = credentials.NewSharedCredentials(opt.Credentials, profile)
	}

	return creds
}

// NewConfig returns the *aws.Config
func NewConfig(opt Option) (*aws.Config, error) {
	var c *aws.Config
	var creds *credentials.Credentials
	var err error
	var region string
	var profile string

	creds = NewCredentials(opt)

	if opt.Profile == "" {
		profile = GetProfile()
	} else {
		profile = opt.Profile
	}

	if opt.Region != "" {
		region = opt.Region
	} else {
		var conf string
		if opt.Config != "" {
			conf = opt.Config
		} else {
			conf = GetSharedConfigFile()
		}

		region, err = GetRegionFromConfigFile(conf, profile)
		if err != nil {
			return c, err
		}

		if region == "" {
			region = GetRegionFromInstanceIdentityDocument()
		}
	}

	c = &aws.Config{
		Credentials: creds,
		Region:      aws.String(region),
	}

	return c, err
}

/*
NewSession returns the *session.Session.

The argument arg Option or *aws.Config
*/
func NewSession(arg ...interface{}) (*session.Session, error) {
	var sess *session.Session
	var sessOpts session.Options
	var c *aws.Config
	var err error

	if len(arg) == 0 {
		return session.NewSession()
	}

	switch val := arg[0].(type) {
	case Option:
		c, err = NewConfig(val)
		if err != nil {
			return sess, err
		}

		sessOpts.Config = *c
		sessOpts.Profile = val.Profile
	case *aws.Config:
		sessOpts.Config = *val
	default:
		return sess, fmt.Errorf("Invalid arg: %T", val)
	}

	return session.NewSessionWithOptions(sessOpts)
}
