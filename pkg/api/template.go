package api

import (
	"github.com/sirupsen/logrus"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
)

func (s *Server) LoadTemplates() error {
	dir := s.cfg.StaticPages + "/templates"
	t, err := template.New("template/").ParseGlob(dir + "/*.gohtml")
	if err != nil {
		return err
	}
	s.templates = t

	return nil
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, templData any) error {
	var rerr error
	defer func() {
		if rerr != nil {
			logrus.WithError(rerr).Error("renderTemplate failed")
		}
	}()

	err := s.templates.ExecuteTemplate(w, name, templData)
	if err != nil {
		if !strings.HasSuffix(name, ".gohtml") {
			p := name
			if name[0] != '/' {
				p = "/" + name
			}
			fullPath := s.cfg.StaticPages + p

			fp, err := os.Open(fullPath)
			if err != nil {
				return err
			}
			_, _ = io.Copy(w, fp)
			_ = fp.Close()
			return nil
		}

		return err
	}

	return nil
}
