module github.com/openclarity/kubeclarity/backend

go 1.17

require (
	github.com/Portshift/dockle v0.3.2-0.20220411110521-ea4a00a6462d
	github.com/Portshift/go-utils v0.0.0-20211213074910-dd69e9ff3e27
	github.com/bxcodec/faker/v3 v3.7.0
	github.com/go-openapi/loads v0.21.0
	github.com/go-openapi/runtime v0.21.1
	github.com/go-openapi/strfmt v0.21.1
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.5.7
	github.com/openclarity/kubeclarity/api v0.0.0
	github.com/openclarity/kubeclarity/runtime_scan v0.0.0
	github.com/openclarity/kubeclarity/runtime_scan/api v0.0.0
	github.com/openclarity/kubeclarity/shared v0.0.0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.10.1
	github.com/urfave/cli v1.22.5
	gorm.io/driver/postgres v1.2.3
	gorm.io/driver/sqlite v1.2.6
	gorm.io/gorm v1.22.5
	gotest.tools v2.2.0+incompatible
	k8s.io/api v0.23.4
	k8s.io/apimachinery v0.23.4
	k8s.io/client-go v0.23.4
)

require (
	cloud.google.com/go/compute v1.5.0 // indirect
	github.com/CycloneDX/cyclonedx-go v0.5.0 // indirect
	github.com/GoogleCloudPlatform/docker-credential-gcr v2.0.5+incompatible // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/anchore/go-rpmdb v0.0.0-20210914181456-a9c52348da63 // indirect
	github.com/anchore/go-version v1.2.2-0.20210903204242-51efa5b487c4 // indirect
	github.com/anchore/packageurl-go v0.0.0-20210922164639-b3fa992ebd29 // indirect
	github.com/anchore/stereoscope v0.0.0-20220128220103-c30d664f2d82 // indirect
	github.com/anchore/syft v0.36.0 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef // indirect
	github.com/aws/aws-sdk-go v1.38.49 // indirect
	github.com/bmatcuk/doublestar/v4 v4.0.2 // indirect
	github.com/containerd/containerd v1.6.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.11.1 // indirect
	github.com/containers/image/v5 v5.19.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v20.10.12+incompatible // indirect
	github.com/docker/distribution v2.8.0+incompatible // indirect
	github.com/docker/docker v20.10.12+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.6.4 // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20210315054119-f66993602bf5 // indirect
	github.com/facebookincubator/nvdtools v0.1.4 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/logr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.20.1 // indirect
	github.com/go-openapi/errors v0.20.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.6 // indirect
	github.com/go-openapi/spec v0.20.4 // indirect
	github.com/go-openapi/swag v0.19.15 // indirect
	github.com/go-openapi/validate v0.20.3 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/golang/snappy v0.0.3 // indirect
	github.com/google/go-containerregistry v0.8.1-0.20220414143355-892d7a808387 // indirect
	github.com/google/go-containerregistry/pkg/authn/kubernetes v0.0.0-20220425181515-fc6ff852e45e // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.10.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.2.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.9.0 // indirect
	github.com/jackc/pgx/v4 v4.14.0 // indirect
	github.com/jessevdk/go-flags v1.5.0 // indirect
	github.com/jinzhu/copier v0.3.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.4 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.14.4 // indirect
	github.com/klauspost/pgzip v1.2.5 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mattn/go-sqlite3 v1.14.9 // indirect
	github.com/mholt/archiver/v3 v3.5.1 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/hashstructure/v2 v2.0.2 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nwaples/rardecode v1.1.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20220114050600-8b9d41f48198 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/scylladb/go-set v1.0.2 // indirect
	github.com/spdx/tools-golang v0.1.0 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/ulikunitz/xz v0.5.10 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	github.com/vifraa/gopom v0.1.0 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20210627031916-db1f5573bbc5 // indirect
	github.com/wagoodman/go-progress v0.0.0-20200807221327-51d465df1451 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	go.mongodb.org/mongo-driver v1.7.5 // indirect
	golang.org/x/crypto v0.0.0-20220214200702-86341886e292 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/oauth2 v0.0.0-20220223155221-ee480838109b // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20220227234510-4e6760a101f9 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20220224211638-0e9765cccd65 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220301145929-1ac2ace0dbf7 // indirect
	google.golang.org/grpc v1.44.0 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/ini.v1 v1.66.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/klog/v2 v2.40.1 // indirect
	k8s.io/kube-openapi v0.0.0-20220124234850-424119656bbf // indirect
	k8s.io/utils v0.0.0-20220210201930-3a6ce19ff2f9 // indirect
	sigs.k8s.io/json v0.0.0-20211208200746-9f7c6b3444d2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

replace (
	github.com/openclarity/kubeclarity/api v0.0.0 => ./../api
	github.com/openclarity/kubeclarity/runtime_k8s_scanner v0.0.0 => ./../runtime_k8s_scanner
	github.com/openclarity/kubeclarity/runtime_scan v0.0.0 => ./../runtime_scan
	github.com/openclarity/kubeclarity/runtime_scan/api v0.0.0 => ./../runtime_scan/api
	github.com/openclarity/kubeclarity/sbom_db/api v0.0.0 => ./../sbom_db/api
	github.com/openclarity/kubeclarity/shared v0.0.0 => ./../shared
)
