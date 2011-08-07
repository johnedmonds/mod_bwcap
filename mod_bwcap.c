#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"

module AP_MODULE_DECLARE_DATA mod_bwcap_module;

typedef struct {
    /*The number of bytes to send before sending 503s.*/
    long long bandwidth_cap;
    /*Path to file where we should store the amount of data sent.*/
    char *scoreboard;
} modbwcap_config;

typedef struct {
    /*The number of bytes sent so far.*/
    long long used_bandwidth;
} modbwcap_state;

/*
 * Handles counting the number of bytes.
 */
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
/*
 * Handles the request by registering the filter that counts bytes.
 * Also cancelles the request if the number of bytes is exceeded.
 */
static int mod_bwcap_method_handler (request_rec *r)
{
    return DECLINED;
}

/*
 * Called to insert the filter that counts the number of bytes.
 */
static int mod_bwcap_insert_filter(request_rec *r)
{
    ap_add_output_filter("mod_bwcap", NULL, r, r->connection);
}

/*
 * Registers hooks and filters to httpd.
 */
static void mod_bwcap_register_hooks(apr_pool_t *p)
{
    ap_register_output_filter("mod_bwcap", mod_bwcap_filter, NULL, AP_FTYPE_TRANSCODE);
    ap_hook_handler(mod_bwcap_method_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_insert_filter(mod_bwcap_insert_filter, NULL, NULL, APR_HOOK_FIRST);
}

static void *mod_bwcap_create_server_config(apr_pool_t *p, server_rec *s)
{
    modbwcap_config *cfg=
        (modbwcap_config*)apr_pcalloc(p, sizeof(modbwcap_config));
    cfg->bandwidth_cap=0;
    return cfg;
}

static const char *set_modbwcap_bandwidth_cap(cmd_parms *params, void *mconfig,
    const char *arg)
{
    modbwcap_config *cfg = ap_get_module_config(params->server->module_config,
        &mod_bwcap_module);
    cfg->bandwidth_cap = atoi(arg);

    return NULL;
}

static const char *set_modbwcap_scoreboard_file(cmd_parms *params, void *mconfig,
    const char *arg)
{
    modbwcap_config *cfg = ap_get_module_config(params->server->module_config,
        &mod_bwcap_module);
    cfg->scoreboard = arg;

    return NULL;
}

static const command_rec mod_bwcap_cmds[] =
{
    AP_INIT_TAKE1(
        "ModuleBWCapBandwidthCap",
        set_modbwcap_bandwidth_cap,
        NULL,
        RSRC_CONF,
        "ModuleBWCapBandwidthCap the maximum number of bytes before we start sending 503s."
    ),
    AP_INIT_TAKE1(
        "ModuleBWCapScoreboardFile",
        set_modbwcap_bandwidth_cap,
        NULL,
        RSRC_CONF,
        "ModuleBWCapScoreboardFile Where to store state information about the total bandwidth used."
    ),
    {NULL}
};

module AP_MODULE_DECLARE_DATA mod_bwcap_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    mod_bwcap_create_server_config,
    NULL,
    mod_bwcap_cmds,
    mod_bwcap_register_hooks
};

