package htmx

func (handler *Handler) BrandingImageSources() []string {
	return handler.config.Branding.ImageSources()
}
