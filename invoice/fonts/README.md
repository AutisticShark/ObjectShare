Invoice PDFs embed the Go font for ordinary documents and Noto Sans TC when
the document needs its Chinese/Japanese glyph coverage. Noto is distributed
under the SIL Open Font License in OFL.txt.

Source: https://github.com/google/fonts/tree/main/ofl/notosanstc

NotoSansTC-Regular.ttf was generated from NotoSansTC[wght].ttf by instantiating
weight 400 with fontTools 4.64.0 and retaining the font's Basic Multilingual
Plane characters (U+0000 through U+FFFF). OpenType layout features are omitted;
invoice text is laid out by the PDF library. The font remains embedded in the
application, and each PDF embeds only the glyphs it uses. This requires no
font installation or font download on the deployed server.
