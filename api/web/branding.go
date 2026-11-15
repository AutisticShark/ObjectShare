package web

func (handler *Handler) BrandingImageSources() []string {
	return handler.config.Branding.ImageSources()
}
