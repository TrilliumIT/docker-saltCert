package zfsdriver

import (
	"fmt"

	"github.com/clinta/go-zfs"
	"github.com/docker/go-plugins-helpers/volume"
)

type ZfsDriver struct {
	volume.Driver
	rds *zfs.Dataset //root dataset
}

func NewZfsDriver(ds string, mp string) (*ZfsDriver, error) {
	props := make(map[string]string)
	props["mountpoint"] = mp

	if !zfs.DatasetExists(ds) {
		rds, err := zfs.CreateDataset(ds, props)
		if err != nil {
			fmt.Errorf("Failed to create root dataset.")
			return nil, err
		}
		return &ZfsDriver{rds: rds}, nil
	}

	rds, err := zfs.GetDataset(ds)
	return &ZfsDriver{rds: rds}, err
}

func (zd *ZfsDriver) Create(req volume.Request) volume.Response {
	dsName := zd.rds.Name + "/" + req.Name

	if zfs.DatasetExists(dsName) {
		return volume.Response{Err: "Volume already exists."}
	}

	_, err := zfs.CreateDataset(dsName, make(map[string]string))

	return volume.Response{Err: err.Error()}
}

func (zd *ZfsDriver) List(req volume.Request) volume.Response {
	var vols []*volume.Volume

	dsl, err := zd.rds.DatasetList()
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	for ds := range dsl {
		mp, err := ds.GetMountpoint()
		if err != nil {
			return volume.Response{Err: err.Error()}
		}
		vols = append(vols, &volume.Volume{Name: ds.Name, Mountpoint: mp})
	}

	return volume.Response{Volumes: vols, Err: ""}
}

func (zd *ZfsDriver) Get(req volume.Request) volume.Response {
	ds, err := zfs.GetDataset(req.Name)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	mp, err := ds.GetMountpoint()
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	return volume.Response{Volume: &volume.Volume{Name: ds.Name, Mountpoint: mp}, Err: ""}
}

func (zd *ZfsDriver) Remove(req volume.Request) volume.Response {
	ds, err := zfs.GetDataset(req.Name)
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	err = ds.Destroy()
	if err != nil {
		return volume.Response{Err: err.Error()}
	}

	return volume.Response{Err: ""}
}

func (zd *ZfsDriver) Path(req volume.Request) volume.Response {
	ds := zd.Get(req)

	if ds.Err != "" {
		return ds
	}

	return volume.Response{Mountpoint: ds.Mountpoint, Err: ""}
}

func (zd *ZfsDriver) Mount(req volume.MountRequest) volume.Response {
	return zd.Path(volume.Request{Name: req.Name})
}

func (zd *ZfsDriver) Unmount(req volume.UnmountRequest) volume.Response {
	return volume.Response{Err: ""}
}

func (zd *ZfsDriver) Capabilities(req volume.Request) volume.Response {
	return volume.Response{Capabilities: volume.Capability{Scope: "local"}}
}
