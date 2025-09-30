package main

import(
  "context"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "time"
  "sync/atomic"
  "encoding/json"
  "flag"
  "strings"
  "encoding/base64"
  "net/http"
  "net/url"
  "log/slog"
  "crypto/tls"
  "crypto/x509"

  "github.com/goharbor/go-client/pkg/sdk/v2.0/models"

  admv1 "k8s.io/api/admission/v1"
  appsv1 "k8s.io/api/apps/v1"
  batchv1 "k8s.io/api/batch/v1"
  corev1 "k8s.io/api/core/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

  "k8s.io/apimachinery/pkg/runtime"
  "k8s.io/apimachinery/pkg/runtime/serializer"
  "k8s.io/client-go/kubernetes"
  "k8s.io/client-go/tools/clientcmd"
  "k8s.io/client-go/rest"
)

//global variables for flags
var (
  allowDeployLabel   string
  harborCACertPath   string
  harborHost         string
  debugMode          bool
  clientCACertPath   string
  kubeconfigPath     string
  port               string = ":8443"
  metricsPort        string = ":9999"
  logLevel           string
  harborInsecureSkipVerify bool
)

//The Secret reosurce name and namespace name in which the harbor credential infomation registered in the K8s cluster 
var (
  namespace   string  = "waok8s-webhook"
  secretName  string  = "harbor-secret"
)

var (
  requiredFlags  map[string]*Flag
  optionalFlags  map[string]*Flag

  logger         *slog.Logger

  //Mapping to log levels to strings
  logLevelDef     = map[string]slog.Level {
    "debug" : slog.LevelDebug,
    "info"  : slog.LevelInfo,
    "warn"  : slog.LevelWarn,
    "error" : slog.LevelError,
  }
)

var (
  scheme       = runtime.NewScheme()
  codecs       = serializer.NewCodecFactory(scheme)
  deserializer = codecs.UniversalDeserializer()
)

var (
  isReady int32
)

type ContainerImage struct {
  Registry   string
  Project    string
  Repository string
  Reference  string
}

type HarborClient struct {
  config *HarborClientConfig
}

type HarborClientConfig struct {
  URL       string
  Insecure  string
  Username  string
  Password  string
}

type dockerConfig struct {
  Auths map[string]dockerAuth `json:"auths"`
}

type dockerAuth struct {
  Username string `json:"username,omitempty"`
  Password string `json:"password,omitempty"`
  Auth     string `json:"auth,omitempty"`
}

type Flag struct {
  Name          string
  Value         any
  DefaultValue  any
  Usage         string
  Required      bool
}

func NewFlag(name string, value any, defaultValue any, usage string) (*Flag) {
  flag := &Flag{
    Name:           name,
    Value:          value,
    DefaultValue:   defaultValue,
    Usage:          usage,
  }
  return flag
}

func init(){
  _ = appsv1.AddToScheme(scheme)
  _ = admv1.AddToScheme(scheme)

  //Usage
  certUsage         := "Specify the certificate file for the webhook server. (Required)"
  keyUsage          := "Specify the private key file for the webhook server. (Required)"
  harborHostUsage   := "Specify the host name of the harbor. (Required)"
  harborCACertUsage := "Specify the CA cert of the harbor registry server."
  logLevelUsage     := "Specify the log level. (debug,info,warn,error)"
  qpsUsage          := "Maximam client QPS to API server."
  burstUsage        := "Maximam client burst throttle."
  labelUsage        := "Specify the harbor label that indicates the deployment si allowed. (Required)"
  debugUsage        := "Enable debug mode for local testing."
  clientCACertUsage := "Speifiy the client CA certficate that signed the client certificate to verify the client with mTLS. (Required)"
  kubeconfigUsage   := "When debug mode is enabled, specify kubeconfig file to get K8s resource."
  harborInsecureSkipVerifyUsage  := "When Harbor use tls and not available CA certificate, Skip tls verify."

  //Initializing structures to handle required arguments
  requiredFlags = map[string]*Flag{
    "webhookCert": NewFlag("cert", new(string), "", certUsage),
    "webhookKey":  NewFlag("key", new(string), "", keyUsage),
    "harborHost":  NewFlag("harbor-host", new(string), "", harborHostUsage),
    "harborAllowDeployLabelName": NewFlag("label-name", new(string), "", labelUsage),
    "clientCACert": NewFlag("client-ca-cert", new(string), "", clientCACertUsage),
  }

  optionalFlags = map[string]*Flag{
    "harborCACert": NewFlag("harbor-ca-cert", new(string), "", harborCACertUsage),
    "logLevel":     NewFlag("log-level", new(string), "info", logLevelUsage),
    "qps":          NewFlag("qps", new(int), 5, qpsUsage),
    "burst":        NewFlag("burst", new(int), 10, burstUsage),
    "debug":        NewFlag("debug", new(bool), false, debugUsage),
    "kubeconfig":   NewFlag("kubeconfig", new(string), "", kubeconfigUsage),
    "harborInsecureSkipVerify" : NewFlag("harbor-skip-tls-verify", new(bool), false, harborInsecureSkipVerifyUsage),
  }

  for _, value := range requiredFlags {
    switch t := value.Value.(type){
      case *string:
        flag.StringVar(t, value.Name, *t, value.Usage)
      case *int:
        flag.IntVar(t, value.Name, *t, value.Usage)
      case *bool:
        flag.BoolVar(t, value.Name, *t, value.Usage)
    }
  }
  for _, value := range optionalFlags {
    switch t := value.Value.(type){
      case *string:
        flag.StringVar(t, value.Name, *t, value.Usage)
      case *int:
        flag.IntVar(t, value.Name, *t, value.Usage)
      case *bool:
        flag.BoolVar(t, value.Name, *t, value.Usage)
    }
  }
}

func initLogSetting(level string) error {
  //confirm the flag for log
  v, ok := logLevelDef[level]
  if !ok {
    return fmt.Errorf("Error: Unknown flag: %s\n", level)
  }
  //log setting
  opts := &slog.HandlerOptions{
    AddSource : true,
    Level     : v,
  }
  handler := slog.NewTextHandler(os.Stdout, opts)
  logger = slog.New(handler)
  slog.SetDefault(logger)
  return nil
}

// confirm required flags
func checkRequiredFlag() error {
  var badFlags []string

  for _, value := range requiredFlags {
    switch v := value.Value.(type) {
      case *string:
        if *v == "" {
          badFlags = append(badFlags, "--" + value.Name)
        }
      case *int:
        if *v == 0 {
          badFlags = append(badFlags, "--" + value.Name)
        }
    }
  }

  if len(badFlags) == 1 {
    args := badFlags[0]
    return fmt.Errorf("Error: %s is required arguments.", args)
  }else if len (badFlags) > 1 {
    args := strings.Join(badFlags,", ")
    return fmt.Errorf("Error: %s are required arguments.", args)
  }

  return nil
}

func checkFileExist(files ...string) error {

  var notExistFiles []string
  for _, file := range files {
    _, err := os.Stat(file)
    fileExist := !os.IsNotExist(err)

    if !fileExist {
      notExistFiles = append(notExistFiles, file)
    }
  }
  if len(notExistFiles) == 0 {
    return nil
  }else {
    str := strings.Join(notExistFiles,", ")
    return fmt.Errorf("Error: No such file: %s", str)
  }
}

// get artifact from harbor
func (c *HarborClient) getHarborArtifact(image *ContainerImage) (*models.Artifact, error) {

  //handling CA cert
  var client *http.Client
  if harborCACertPath != "" {

    if harborInsecureSkipVerify {
      return nil, fmt.Errorf("Exist Harbor CA cert, but harborInsecureSkipVerify flag is true")
    }

    caCert, err := ioutil.ReadFile(harborCACertPath)
    if err != nil {
      return nil, fmt.Errorf("Error reading harbor CA cert: %v\n", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
      return nil, fmt.Errorf("Failed to append harbor CA cert to pool")
    }

    tlsConfig := &tls.Config{
      RootCAs: caCertPool,
    }

    transport := &http.Transport{
      TLSClientConfig: tlsConfig,
    }

    client = &http.Client{
      Transport: transport,
      Timeout:   10 * time.Second,
    }

  }else if harborCACertPath == "" && harborInsecureSkipVerify{

    client = &http.Client{
      Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
          InsecureSkipVerify: true,
        },
      },
    }

  }else {
    client = &http.Client{}
  }

  basePath := "/api/v2.0/projects/" + image.Project + "/repositories/" + image.Repository + "/artifacts/" + image.Reference

  parsedURL, err := url.Parse(c.config.URL)
  if err != nil {
    return nil, err
  }

  queryParams := url.Values{}
  queryParams.Add("with_label", "true")

  parsedURL.RawQuery = queryParams.Encode()
  parsedURL.Path = basePath

  ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
  defer cancel()

  req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
  if err != nil {
    return nil, err
  }

  req.SetBasicAuth(c.config.Username, c.config.Password)
  req.Header.Add("accept", "application/json")

  resp, err := client.Do(req)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  body, err := ioutil.ReadAll(resp.Body)
  if err != nil {
    return nil, err
  }

  var artifact models.Artifact
  var respError models.Errors
  if resp.StatusCode == http.StatusOK {
    if err := json.Unmarshal(body, &artifact); err != nil {
      return nil,err
    }
  } else {
    if err := json.Unmarshal(body, &respError); err != nil {
      return nil,err
    }
    var errorStr string
    for _, value := range respError.Errors {
      errorStr += value.Message + "."
    }
    return nil, fmt.Errorf("Cannot Get Artifact: response from Harbor: %s", errorStr )
  }
  return &artifact, nil
}

//Check if the image retrived from the harbor is labeld
func (c *HarborClient) judgeAllowDeployImage(images []string) (bool, error){
  var labelFlag bool

  for _, image := range images {

      parsedImage, err := parseDockerImageURL(image)

      if err != nil {
        return false, err
      }

      payload, err := c.getHarborArtifact(parsedImage)
      if err != nil {
        return false, err
      }

      labels := payload.Labels
      labelFlag = false
      for _, value := range labels {
        if value.Name == allowDeployLabel {
          logger.Debug(fmt.Sprintf("The label %s is found! image: %s", value.Name, image))
          labelFlag = true
          break
        }
      }

      if labelFlag == false {
        return false, fmt.Errorf("Not found the label: %s, image: %s", allowDeployLabel, image)
      }
  }
  return labelFlag, nil
}

func parseDockerImageURL(imageURL string) (*ContainerImage, error){

  var (
    image   string
    host    string
    project string
    repo    string
    ref     string
  )

  atRef := strings.Index(imageURL, "@")
  colonRef := strings.LastIndex(imageURL, ":")

  if atRef != -1 {
    ref = imageURL[atRef+1:]
    image = imageURL[:atRef]
  } else if colonRef != -1 && strings.Count(imageURL[colonRef:], "/") == 0 {
    ref = imageURL[colonRef+1:]
    image = imageURL[:colonRef]
  } else {
    // no specified tag
    ref = ""
  }

  // separate "/"
  parts := strings.SplitN(image, "/", 3)
  logger.Debug(fmt.Sprintf("%s", image))

  if len(parts) > 2 {
    host = parts[0]
    project = parts[1]
    repo = parts[2]
  } else {
    return nil, fmt.Errorf("invalid image URL: %s", imageURL)
  }

  if strings.Contains(repo, "/") {
    // encode URL if repository contains "/".
    repo = url.QueryEscape(repo)
  }

  dockerImage := &ContainerImage{
    Registry:   host,
    Project:    project,
    Repository: repo,
    Reference:  ref,
  }
  return dockerImage, nil
}

func extractImagesFromPodSpec(podSpec *corev1.PodSpec) []string {
  var images []string

  //for init container images.
  for _, container := range podSpec.InitContainers {
    images = append(images, container.Image)
  }

  //for container images.
  for _, container := range podSpec.Containers {
    images = append(images, container.Image)
  }

  //for ephemeral container images.
  for _, container := range podSpec.EphemeralContainers {
    images = append(images, container.Image)
  }
  return images
}

func getSecret(ctx context.Context, clientset *kubernetes.Clientset, namespace, secretName string) (*corev1.Secret, error) {
  secret, err := clientset.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
  if err != nil {
    return nil, fmt.Errorf("Cannot get secret: %w", err)
  }
  return secret, nil
}

func getDockerAuth(dockerconfig *dockerConfig, registryHost string) (string, string, error) {
  var username, password string

  for registry, auth := range dockerconfig.Auths {
    if registry == registryHost {
      if auth.Username != "" && auth.Password != "" {
        username = auth.Username
        password = auth.Password

      } else if auth.Auth != "" {
        user, pass, err := decodeDockerAuth(auth.Auth)
        if err !=nil {
          return "", "", err
        }
        username = user
        password = pass
      }
      return username, password, nil
    }
  }
  return "", "", fmt.Errorf("Cannot find host: %s", registryHost)
}

func decodeDockerAuth(auth string) (string, string, error) {
  decodeAuth, err := base64.StdEncoding.DecodeString(auth)
  if err != nil {
    return "", "", fmt.Errorf("faild to decode base64 docker auth: %w", err)
  }

  sprit := strings.Split(string(decodeAuth), ":")
  if len(sprit) !=2 {
    return "", "", fmt.Errorf("invaid auth string")
  }

  return sprit[0], sprit[1], nil
}

func handleAdmissionReview(w http.ResponseWriter, r *http.Request) {
  var (
  allowDeployFlag = false
  hclient = &HarborClient{}
  harborClientConf = &HarborClientConfig{}

  username, password string
  err error
  dockerconfigjson []byte
  dockerConf dockerConfig
  harborSecret *corev1.Secret
  clientset *kubernetes.Clientset
  config *rest.Config
  images []string
  badImages []string
  kind string
  req admv1.AdmissionReview
  )

  logger.Info("Got the request /validate from client.")

  var body []byte
  if r.Body != nil {
    if data, err := io.ReadAll(r.Body); err != nil {
      http.Error(w, err.Error(), http.StatusBadRequest)
      logger.Error(err.Error())
      return
    }else {
      body = data
    }
  }

  if len(body) == 0 {
    logger.Error("Request body is empty.")
    http.Error(w, "Request body is empty.", http.StatusBadRequest)
    return
  }

  contentType := r.Header.Get("Content-Type")
  if contentType != "application/json" {
    logger.Error(fmt.Sprintf("Invalid Content-Type: %s", contentType))
    http.Error(w, "Invalid Content-Type.", http.StatusUnsupportedMediaType)
    return
  }

  if logLevel == "debug" {
    var reqObj json.RawMessage
    if err := json.Unmarshal(body, &reqObj); err != nil {
      logger.Error(fmt.Sprintf("Faild to decode json to json raw message:%v", err))
      http.Error(w, "Faild to decode json to json raw message.", http.StatusBadRequest)
      return
    }
    reqJson, err := json.MarshalIndent(&reqObj, "", "\t")
    if err != nil {
      logger.Error(fmt.Sprintf("Faild to format json indent:%v", err))
      http.Error(w, "Faild to format json indent.", http.StatusBadRequest)
      return
    }
    fmt.Printf("%v\n", string(reqJson))
  }

  if _, _, err := deserializer.Decode(body, nil, &req); err != nil {
    logger.Error(err.Error())
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }

  obj := req.Request.Object.Raw
  kind = req.Request.Kind.Kind
  switch kind {
    case "Deployment":
      logger.Debug(kind)
      deploy := appsv1.Deployment{}
      if _, _, err := deserializer.Decode(obj, nil, &deploy); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&deploy.Spec.Template.Spec)
    case "StatefulSet":
      logger.Debug(kind)
      sts := appsv1.StatefulSet{}
      if _, _, err := deserializer.Decode(obj, nil, &sts); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&sts.Spec.Template.Spec)
    case "DaemonSet":
      logger.Debug(kind)
      daemon := appsv1.DaemonSet{}
      if _, _, err := deserializer.Decode(obj, nil, &daemon); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&daemon.Spec.Template.Spec)
    case "ReplicaSet":
      logger.Debug(kind)
      rs := appsv1.ReplicaSet{}
      if _, _, err := deserializer.Decode(obj, nil, &rs); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&rs.Spec.Template.Spec)
    case "CronJob":
      logger.Debug(kind)
      cj := batchv1.CronJob{}
      if _, _, err := deserializer.Decode(obj, nil, &cj); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&cj.Spec.JobTemplate.Spec.Template.Spec)
    case "Job":
      logger.Debug(kind)
      job := batchv1.Job{}
      if _, _, err := deserializer.Decode(obj, nil, &job); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&job.Spec.Template.Spec)
    case "Pod":
      logger.Debug(kind)
      pod := corev1.Pod{}
      if _, _, err := deserializer.Decode(obj, nil, &pod); err != nil {
        logger.Error(fmt.Sprintf("Decode Error:", err.Error()))
        goto Error
      }
      images = extractImagesFromPodSpec(&pod.Spec)
    default:
      logger.Debug("invalid kind request.")
      goto Error
  }
  logger.Debug(fmt.Sprintf("container image: %s", images[:]))

  //Check whether images from hosts other than the one specified by the '--harbor-host' option are included
  for _, image := range images {
    reqParsedImg, err := parseDockerImageURL(image)
    if err != nil {
      logger.Error(err.Error())
      goto Error
    }
    if reqParsedImg.Registry != harborHost {
      badImages = append(badImages, image)
    }
  }

  if len(badImages) > 0 {
    logger.Error(fmt.Sprintf("Request contains bad image: %s", badImages[:]))
    goto Error
  }

  //Obtain the Secret resoruce as harbor authentication info
  logger.Debug("Setting kubernetes client config.")

  if debugMode {
    buildconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
    if err != nil {
      logger.Error(fmt.Sprintf("Faild to get BuildConfig: %v", err))
      goto Error
    }
    config = buildconfig
  } else {
    inclusterconfig, err := rest.InClusterConfig()
    if err != nil {
      logger.Error(fmt.Sprintf("Faild to get InClusterConfig: %v", err))
      goto Error
    }
    config = inclusterconfig
  }

  config.QPS = float32(*optionalFlags["qps"].Value.(*int))
  config.Burst = *optionalFlags["burst"].Value.(*int)

  clientset, err = kubernetes.NewForConfig(config)
  if err !=nil {
    logger.Error(fmt.Sprintf("Faild to create kubernetes client: %v", err))
    goto Error
  }

  logger.Debug("Get secret object of harbor registry from kubernetes cluster.")
  harborSecret, err = getSecret(context.Background(), clientset, namespace, secretName)
  if err != nil {
    logger.Error(err.Error())
    goto Error
  }

  dockerconfigjson = harborSecret.Data[".dockerconfigjson"]
  if err := json.Unmarshal([]byte(dockerconfigjson), &dockerConf); err != nil {
    logger.Error("Couldn't parse json.")
    goto Error
  }

  username, password, err = getDockerAuth(&dockerConf, harborHost)
  if err != nil {
    logger.Error(err.Error())
    goto Error
  }

  //Create harbor client
  harborClientConf = &HarborClientConfig{
    URL      : *requiredFlags["harborHost"].Value.(*string),
    Username : username,
    Password : password,
  }
  hclient = &HarborClient{config:harborClientConf}

  logger.Debug("Get image labels from harbor and determine if it is deployable.")

  allowDeployFlag, err = hclient.judgeAllowDeployImage(images)
  if err != nil {
    logger.Error(err.Error())
    goto Error
  }

  if allowDeployFlag {
    logger.Info(fmt.Sprintf("Allow deploy: %s", images[:]))
  }else {
    logger.Info("Not allow deploy.")
  }

Error:
  //Create response
  logger.Debug("Return response.")
  var resp admv1.AdmissionReview
  if allowDeployFlag {
    resp = admv1.AdmissionReview{
      TypeMeta: metav1.TypeMeta{
        Kind: "AdmissionReview",
        APIVersion: "admission.k8s.io/v1",
      },
      Response: &admv1.AdmissionResponse{
        UID: req.Request.UID,
        Allowed: allowDeployFlag,
      },
    }
  } else {
    resp = admv1.AdmissionReview{
      TypeMeta: metav1.TypeMeta{
        Kind: "AdmissionReview",
        APIVersion: "admission.k8s.io/v1",
      },
      Response: &admv1.AdmissionResponse{
        UID: req.Request.UID,
        Allowed: allowDeployFlag,
        Result: &metav1.Status{
          Message: fmt.Sprintf("%v", err),
        },
      },
    }
  }

  respBody, err := json.Marshal(resp)
  if err != nil {
    logger.Error(err.Error())
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  w.Header().Set("Content-Type","application/json")
  w.WriteHeader(http.StatusOK)
  w.Write(respBody)
}

func handleLiveness(w http.ResponseWriter, r *http.Request) {
  logger.Debug("Got the request /healthz from client.")
  w.WriteHeader(http.StatusOK)
  logger.Debug("Application is healthy.")
  fmt.Fprintf(w, "OK")
}

func handleReadiness(w http.ResponseWriter, r *http.Request) {
  logger.Debug("Got the request /ready from client.")
  if atomic.LoadInt32(&isReady) == 1 {
    w.WriteHeader(http.StatusOK)
    logger.Debug("Application is ready.")
    fmt.Fprintf(w, "Ready")
  } else {
    w.WriteHeader(http.StatusServiceUnavailable)
    logger.Debug("Application is NOT ready!")
    fmt.Fprintf(w, "Not Ready")
  }
}

func main(){

  readyCh := make(chan bool)
  go func(ch chan bool) {
    ready := <-ch
    if ready {
      atomic.StoreInt32(&isReady, 1)
      fmt.Println("app is ready...")
    }
  }(readyCh)

  //parse flag
  flag.Parse()
  //check flags
  if err := checkRequiredFlag(); err != nil {
    fmt.Println(err)
    flag.Usage()
    os.Exit(1)
  }

  //init logging
  logLevel = *optionalFlags["logLevel"].Value.(*string)
  if err := initLogSetting(logLevel); err != nil {
    fmt.Println(err)
    flag.Usage()
    os.Exit(1)
  }

  /*
  logger.Debug("DEBUG")
  logger.Info("INFO")
  logger.Warn("WARN")
  logger.Error("ERROR")
  */

  certPath        := *requiredFlags["webhookCert"].Value.(*string)
  keyPath         := *requiredFlags["webhookKey"].Value.(*string)
  allowDeployLabel = *requiredFlags["harborAllowDeployLabelName"].Value.(*string)
  harborCACertPath = *optionalFlags["harborCACert"].Value.(*string)
  clientCACertPath = *requiredFlags["clientCACert"].Value.(*string)
  debugMode        = *optionalFlags["debug"].Value.(*bool)
  kubeconfigPath   = *optionalFlags["kubeconfig"].Value.(*string)
  harborURL, err := url.Parse(*requiredFlags["harborHost"].Value.(*string))
  if err != nil {
    logger.Error("harbor host parse error.")
    os.Exit(1)
  }
  harborHost       = harborURL.Host
  harborInsecureSkipVerify   = *optionalFlags["harborInsecureSkipVerify"].Value.(*bool)

  if debugMode && kubeconfigPath == "" {
    fmt.Println(fmt.Errorf("Error: debug flag is true, but kubeconfig is not specified."))
    flag.Usage()
    os.Exit(1)
  } else if debugMode && kubeconfigPath != "" {
    if err := checkFileExist(kubeconfigPath); err != nil {
      logger.Error(err.Error())
      os.Exit(1)
    }
    logger.Info(fmt.Sprintf("debug mode is active."))
    logger.Info(fmt.Sprintf("kubeconfig : %s", kubeconfigPath))
  }

  if err := checkFileExist(certPath, keyPath, clientCACertPath); err != nil {
    logger.Error(err.Error())
    os.Exit(1)
  }

  logger.Info(fmt.Sprintf("webhook server cert: %s", certPath))
  logger.Info(fmt.Sprintf("webhook server key: %s", keyPath))
  logger.Info(fmt.Sprintf("harbor host: %s", harborURL))
  logger.Info(fmt.Sprintf("log level: %s", logLevel))
  logger.Info(fmt.Sprintf("Client(apiserver) CA cert: %s", clientCACertPath))

  if len(harborCACertPath) != 0 {
    if err := checkFileExist(harborCACertPath); err != nil {
      logger.Error(err.Error())
      os.Exit(1)
    }
    logger.Info(fmt.Sprintf("Harbor CA cert: %s", harborCACertPath))
  }

  logger.Info(fmt.Sprintf("Harbor skip tls verify: %s", harborInsecureSkipVerify))

  cert, err := tls.LoadX509KeyPair(certPath, keyPath)
  if err != nil {
    logger.Error(fmt.Sprintf("Faild to load key pair: %w", err))
    os.Exit(1)
  }

  logger.Info("Loading client CA cert...")
  clientCACert, err := ioutil.ReadFile(clientCACertPath)
  if err != nil {
    logger.Error(fmt.Sprintf("Cannot load client CA cert: %w", err))
    os.Exit(1)
  }

  clientCACertPool := x509.NewCertPool()
  if !clientCACertPool.AppendCertsFromPEM(clientCACert) {
    logger.Error(fmt.Sprintf("Failed to append client CA cert to pool"))
    os.Exit(1)
  }

  tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    clientCACertPool,
    ClientAuth:   tls.RequireAndVerifyClientCert,
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/validate", handleAdmissionReview)

  server := &http.Server{
    Addr:      port,
    TLSConfig: tlsConfig,
    Handler:   mux,
  }

  logger.Info(fmt.Sprintf("Starting webhook server https://127.0.0.1:%s", port))

  go func() {
    if err := server.ListenAndServeTLS("", ""); err != nil{
      logger.Error(err.Error())
      os.Exit(1)
    }
  }()

  go func(ch chan bool) {
    logger.Info(fmt.Sprintf("Starting metrics https://127.0.0.1:%s", metricsPort))
    http.HandleFunc("/ready", handleReadiness)
    http.HandleFunc("/healthz", handleLiveness)
    ch <- true
    close(ch)
    if err := http.ListenAndServe(metricsPort, nil); err != nil {
      logger.Error(err.Error())
      os.Exit(1)
    }
  }(readyCh)

  select{}
}
