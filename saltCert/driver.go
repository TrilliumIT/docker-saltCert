package saltCert

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
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

func (d *Driver) Create(req *volume.CreateRequest) error {
	log.WithField("Request", spew.Sdump(req)).Debug("Create")

	if _, err := os.Stat(volDir + req.Name); err != nil {
		if err = os.MkdirAll(volDir+"/"+req.Name, 660); err != nil {
			return err
		}
	}

	f, err := os.Create(volDir + "/" + req.Name + "/req.json")
	if err != nil {
		return err
	}
	defer f.Close()

	e := json.NewEncoder(f)
	if err = e.Encode(req); err != nil {
		return err
	}
	return nil
}

func (d *Driver) List() (*volume.ListResponse, error) {
	log.Debug("List")
	var vols []*volume.Volume

	fs, err := ioutil.ReadDir(volDir)
	if err != nil {
		return nil, err
	}

	for _, f := range fs {
		vols = append(vols, &volume.Volume{
			Name:       f.Name(),
			Mountpoint: volDir + "/" + f.Name(),
		})
	}

	return &volume.ListResponse{Volumes: vols}, nil
}

func (d *Driver) Get(req *volume.GetRequest) (*volume.GetResponse, error) {
	log.WithField("Request", spew.Sdump(req)).Debug("Get")

	_, err := os.Stat(volDir + "/" + req.Name)
	if err != nil {
		return nil, err
	}

	return &volume.GetResponse{
		Volume: &volume.Volume{
			Name:       req.Name,
			Mountpoint: volDir + "/" + req.Name,
		},
	}, nil
}

func (d *Driver) Remove(req *volume.RemoveRequest) error {
	log.WithField("Request", spew.Sdump(req)).Debug("Remove")
	err := os.RemoveAll(volDir + "/" + req.Name)
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Path(req *volume.PathRequest) (*volume.PathResponse, error) {
	log.WithField("Request", spew.Sdump(req)).Debug("Path")
	res, err := d.Get(&volume.GetRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}
	return &volume.PathResponse{Mountpoint: res.Volume.Mountpoint}, nil
}

func (d *Driver) Mount(req *volume.MountRequest) (*volume.MountResponse, error) {
	log.WithField("Request", spew.Sdump(req)).Debug("Mount")

	cOpts := &volume.CreateRequest{}
	cFile, err := os.Open(volDir + "/" + req.Name + "/req.json")
	if err != nil {
		return nil, err
	}
	defer cFile.Close()

	err = json.NewDecoder(cFile).Decode(cOpts)
	if err != nil {
		return nil, err
	}

	log.WithField("cOpts", spew.Sdump(cOpts)).Debug("Options decoded")

	keyCmd := exec.Command("salt-call", "x509.create_private_key", "--retcode-passthrough", "path="+volDir+"/"+req.Name+"/key.pem")
	certCmd := exec.Command("salt-call", "x509.create_certificate", "--retcode-passthrough", "path="+volDir+"/"+req.Name+"/cert.pem", "public_key="+volDir+"/"+req.Name+"/key.pem")
	for k, v := range cOpts.Options {
		if strings.HasPrefix(k, "key") {
			keyCmd.Args = append(keyCmd.Args, strings.TrimPrefix(k, "key")+"="+v)
		} else {
			certCmd.Args = append(certCmd.Args, k+"="+v)
		}
	}

	log.WithField("Cmd", keyCmd).Debug("Generating Private Key")
	out, err := keyCmd.CombinedOutput()
	if err != nil {
		log.WithField("Salt Output", string(out)).Error("Error running salt command to generate key")
		return nil, err
	}

	log.WithField("Cmd", certCmd).Debug("Generating Cert")
	out, err = certCmd.CombinedOutput()
	if err != nil {
		log.WithField("Salt Output", string(out)).Error("Error running salt command to generate key")
		return nil, err
	}

	path, err := d.Path(&volume.PathRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}
	return &volume.MountResponse{Mountpoint: path.Mountpoint}, nil
}

func (d *Driver) Unmount(req *volume.UnmountRequest) error {
	log.WithField("Request", spew.Sdump(req)).Debug("Unmount")
	err := os.Remove(volDir + "/" + req.Name + "/key.pem")
	if err != nil {
		return err
	}
	err = os.Remove(volDir + "/" + req.Name + "/cert.pem")
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) Capabilities() *volume.CapabilitiesResponse {
	log.Debug("Capabilites")
	return &volume.CapabilitiesResponse{Capabilities: volume.Capability{Scope: "local"}}
}
