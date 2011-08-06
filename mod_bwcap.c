#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"

static int mod_bwcap_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv;
    
    for (b = APR_BRIGADE_FIRST(bb);	b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b) )
    {
        if(b->length == (apr_size_t)-1)
        {
            apr_size_t len;
            const char *ignored;
            apr_read_type_e eblock = APR_NONBLOCK_READ;
            rv = apr_bucket_read(b, &ignored, &len, eblock);
            if (rv == APR_SUCCESS) {
                fprintf(stderr,"bucket size:%d\n",len);
            }
        }
        else
        {
            fprintf(stderr,"bucket size:%d\n",b->length);
        }
    }
    fflush(stderr);
    return ap_pass_brigade(f->next, bb);
}
static int mod_bwcap_method_handler (request_rec *r)
{
    ap_add_output_filter("mod_bwcap", NULL, r, r->connection);
    fprintf(stderr,"apache2_mod_bwcap:handling request.\n");
    fflush(stderr);
    return DECLINED;
}

static void mod_bwcap_register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("mod_bwcap", mod_bwcap_filter, NULL, AP_FTYPE_TRANSCODE);
    ap_hook_handler(mod_bwcap_method_handler, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA mod_bwcap_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    mod_bwcap_register_hooks
};

