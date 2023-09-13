package handler

import (
	"html/template"
	"io"
	"io/fs"

	"github.com/labstack/echo/v4"
)

type TemplateRenderer struct {
	templates  *template.Template
	webContent fs.FS
}

func NewTemplateRenderer(c fs.FS) *TemplateRenderer {
	return &TemplateRenderer{
		templates:  template.Must(template.ParseFS(c, "*.html")),
		webContent: c,
	}
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	// https://stackoverflow.com/questions/36617949/how-to-use-base-template-file-for-golang-html-template
	tmpl := template.Must(t.templates.Clone())
	tmpl = template.Must(tmpl.ParseFS(t.webContent, name))
	return tmpl.ExecuteTemplate(w, name, data)
}
