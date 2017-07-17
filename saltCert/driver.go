package saltCert

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
)

const volDir = "/var/lib/docker-volumes/saltCert"

type Driver struct {
	volume.Driver
}

func NewDriver() (*Driver, error) {
	log.SetLevel(log.DebugLevel)
	log.Debug("Creating new Driver.")

	return &Driver{}, nil
}

func (d *Driver) Create(req volume.Request) volume.Response {
	log.WithField("Request", req).Debug("Create")

	if _, err := os.Stat(volDir + req.Name); err != nil {
		if err = os.MkdirAll(volDir+req.Name, 660); err != nil {
			return volume.Response{Err: err.Error()}
		}
	}

	f, err := os.Create(volDir + "/" + req.Name + "/req.json")
	if err != nil {
		return volume.Response{Err: err.Error()}
	}
	defer f.Close()

	e := json.NewEncoder(f)
	if err = e.Encode(req.Options); err != nil {
		return volume.Response{Err: err.Error()}
	}
	return volume.Response{}
}

func (d *Driver) List(req volume.Request) volume.Response {
	log.WithField("Requst", req).Debug("List")
	var vols []*volume.Volume

	fs, err := ioutil.ReadDir(volDir)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	for _, f := range fs {
		vols = append(vols, &volume.Volume{
			Name:       f.Name(),
			Mountpoint: volDir + "/" + f.Name(),
		})
	}

	return volume.Response{Volumes: vols}
}

func (d *Driver) Get(req volume.Request) volume.Response {
	log.WithField("Request", req).Debug("Get")

	_, err := os.Stat(volDir + "/" + req.Name)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	return volume.Response{
		Volume: &volume.Volume{
			Name:       req.Name,
			Mountpoint: volDir + "/" + req.Name,
		},
	}
}

func (d *Driver) Remove(req volume.Request) volume.Response {
	log.WithField("Request", req).Debug("Remove")
	err := os.RemoveAll(volDir + "/" + req.Name)
	return volume.Response{Err: err.Error()}
}

func (d *Driver) Path(req volume.Request) volume.Response {
	log.WithField("Request", req).Debug("Path")
	res := d.Get(req)

	if res.Err != "" {
		return res
	}

	return volume.Response{Mountpoint: res.Volume.Mountpoint, Err: ""}
}

func (d *Driver) Mount(req volume.MountRequest) volume.Response {
	log.WithField("Request", req).Debug("Mount")

	cOpts := &volume.Request{}
	cFile, err := os.Open(volDir + "/" + req.Name + "/req.json")
	if err != nil {
		return volume.Response{Err: err.Error()}
	}
	defer cFile.Close()

	err = json.NewDecoder(cFile).Decode(cOpts)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	keyCmd := exec.Command("salt-call", "x509.create_private_key", "--retcode-passthrough", "path=/"+volDir+"/"+req.Name+"/key.pem")
	certCmd := exec.Command("salt-call", "x509.create_certificate", "--retcode-passthrough", "path=/"+volDir+"/"+req.Name+"/cert.pem", "public_key=/"+volDir+"/"+req.Name+"/key.pem")
	for k, v := range cOpts.Options {
		if strings.HasPrefix(k, "key") {
			keyCmd.Args = append(keyCmd.Args, strings.TrimPrefix(k, "key")+"="+v)
		} else {
			certCmd.Args = append(certCmd.Args, k+"="+v)
		}
	}

	out, err := keyCmd.CombinedOutput()
	if err != nil {
		log.WithField("Salt Output", string(out)).Error("Error running salt command to generate key")
		return volume.Response{Err: err.Error()}
	}

	out, err = certCmd.CombinedOutput()
	if err != nil {
		log.WithField("Salt Output", string(out)).Error("Error running salt command to generate key")
		return volume.Response{Err: err.Error()}
	}

	return d.Path(volume.Request{Name: req.Name})
}

func (d *Driver) Unmount(req volume.UnmountRequest) volume.Response {
	log.WithField("Request", req).Debug("Unmount")
	ret := volume.Response{}
	ret.Err += os.Remove(volDir + "/" + req.Name + "/key.pem").Error()
	ret.Err += os.Remove(volDir + "/" + req.Name + "/cert.pem").Error()
	return ret
}

func (d *Driver) Capabilities(req volume.Request) volume.Response {
	log.WithField("Request", req).Debug("Capabilites")
	return volume.Response{Capabilities: volume.Capability{Scope: "local"}}
}
