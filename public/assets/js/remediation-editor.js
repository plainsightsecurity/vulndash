// Rich-text editor for the admin "Custom remediation" panel on
// vulnerability_detail.php. Turns the textarea[data-rich-editor] there into a
// CKEditor 5 instance (vendored, self-hosted UMD build in
// /assets/vendor/ckeditor5/ - the CSP only allows same-origin scripts, and
// CKEditor's 'GPL' licence key only works with a self-hosted build anyway).
//
// The plugin set is deliberately limited to what Qualys's own remediation
// HTML uses and what Helpers::sanitizeVendorHtml() keeps: paragraphs,
// headings, bold/italic/underline, inline code, links, lists, block quotes
// and tables. Anything the editor can produce therefore survives the
// server-side sanitiser that every save goes through, so what the admin sees
// here is what clients see. Images, media embeds, font colours etc. are left
// out because the sanitiser would strip them on save.
//
// If the bundle fails to load, nothing here runs and the textarea stays
// visible as a raw-HTML box - still saved through the same sanitiser.
(function () {
    var textarea = document.querySelector('textarea[data-rich-editor]');
    var CK = window.CKEDITOR;
    if (!textarea || !CK || !CK.ClassicEditor) {
        return;
    }

    CK.ClassicEditor.create(textarea, {
        licenseKey: 'GPL',
        plugins: [
            CK.Essentials, CK.Paragraph, CK.Heading,
            CK.Bold, CK.Italic, CK.Underline, CK.Code,
            CK.Link, CK.AutoLink,
            CK.List, CK.BlockQuote,
            CK.Table, CK.TableToolbar,
            CK.PasteFromOffice
        ],
        toolbar: {
            items: [
                'heading', '|',
                'bold', 'italic', 'underline', 'code', '|',
                'link', 'bulletedList', 'numberedList', 'blockQuote', 'insertTable', '|',
                'undo', 'redo'
            ],
            shouldNotGroupWhenFull: false
        },
        heading: {
            options: [
                { model: 'paragraph', title: 'Paragraph', class: 'ck-heading_paragraph' },
                { model: 'heading3', view: 'h3', title: 'Heading', class: 'ck-heading_heading3' },
                { model: 'heading4', view: 'h4', title: 'Subheading', class: 'ck-heading_heading4' }
            ]
        },
        link: {
            // A bare "www.vendor.com/patch" typed into the link box becomes
            // https://..., rather than a relative link back into this app.
            defaultProtocol: 'https://'
        },
        table: {
            contentToolbar: ['tableColumn', 'tableRow', 'mergeTableCells']
        }
    }).then(function (editor) {
        // ClassicEditor syncs the textarea on submit itself; doing it here as
        // well makes the save independent of that internal behaviour.
        var form = textarea.form;
        if (form) {
            form.addEventListener('submit', function () {
                editor.updateSourceElement();
            });
        }
    }).catch(function (err) {
        // Leave the plain textarea in place (see the header comment) and keep
        // the reason visible to whoever opens the console.
        textarea.style.display = '';
        if (window.console) {
            window.console.error('Custom remediation editor failed to start:', err);
        }
    });
})();
