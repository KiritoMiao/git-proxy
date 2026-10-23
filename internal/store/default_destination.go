package store

import (
	"database/sql"
	"errors"
)

// DefaultDestination supplies the upstream for repositories without an explicit route.
type DefaultDestination struct {
	Enabled         bool   `json:"enabled"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	RemoteUser      string `json:"remote_user"`
	HostFingerprint string `json:"host_fingerprint"`
	ReadOnly        bool   `json:"read_only"`
}

func defaultDestination(tx *sql.Tx) (DefaultDestination, error) {
	var d DefaultDestination
	err := tx.QueryRow("SELECT enabled,host,port,remote_user,host_fingerprint,read_only FROM default_destination WHERE id=1").Scan(&d.Enabled, &d.Host, &d.Port, &d.RemoteUser, &d.HostFingerprint, &d.ReadOnly)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultDestination{Host: "github.com", Port: 22, RemoteUser: "git"}, nil
	}
	if err != nil {
		return DefaultDestination{}, databaseError(err)
	}
	return d, nil
}

// GetDefaultDestination reads the global destination for an enabled administrator.
func (s *Store) GetDefaultDestination(actorID string) (DefaultDestination, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return DefaultDestination{}, databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return DefaultDestination{}, err
	}
	return defaultDestination(tx)
}

// SaveDefaultDestination replaces the global destination for an enabled administrator.
func (s *Store) SaveDefaultDestination(actorID string, d DefaultDestination) error {
	tx, err := s.db.Begin()
	if err != nil {
		return databaseError(err)
	}
	defer tx.Rollback()
	if _, err = actor(tx, actorID, true); err != nil {
		return err
	}
	if d.Port == 0 {
		d.Port = 22
	}
	if d.RemoteUser == "" {
		d.RemoteUser = "git"
	}
	m := Mapping{Host: d.Host, Port: d.Port, RemoteUser: d.RemoteUser, HostFingerprint: d.HostFingerprint}
	if err = validateMappingDestination(&m, d.Enabled); err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO default_destination(id,enabled,host,port,remote_user,host_fingerprint,read_only)
	 VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
	 enabled=excluded.enabled,host=excluded.host,port=excluded.port,remote_user=excluded.remote_user,
	 host_fingerprint=excluded.host_fingerprint,read_only=excluded.read_only`, d.Enabled, m.Host, m.Port, m.RemoteUser, m.HostFingerprint, d.ReadOnly)
	if err != nil {
		return databaseError(err)
	}
	return commit(tx)
}
