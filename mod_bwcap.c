#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"
#include "apr_shm.h"

module AP_MODULE_DECLARE_DATA mod_bwcap_module;

typedef struct {
    /*The number of bytes to send before sending 503s.*/
    long long bandwidth_cap;
    /*Path to file where we should store the amount of data sent.*/
    char *scoreboard;
    /*The pool used to create the shared memory.*/
    apr_pool_t *p;
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
    
    modbwcap_state *state;
    apr_shm_t *mem;
    modbwcap_config *cfg = ap_get_module_config(f->r->server->module_config,
        &mod_bwcap_module);
        
    apr_shm_attach(&mem, cfg->scoreboard, cfg->p);
    state=apr_shm_baseaddr_get(mem);
    
    long long bucket_size=0;
    
    for (b = APR_BRIGADE_FIRST(bb);	b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b) )
    {
        if(b->length == (apr_size_t)-1)
        {
            apr_size_t len;
            const char *ignored;
            apr_read_type_e eblock = APR_NONBLOCK_READ;
            rv = apr_bucket_read(b, &ignored, &len, eblock);
            if (rv == APR_SUCCESS)
            {
                bucket_size=len;
            }
        }
        else
        {
            bucket_size=b->length;
        }
    }
    state->used_bandwidth += bucket_size;
    
    fprintf(stderr,"bucket size:%d\n",bucket_size);
    fprintf(stderr,"total bandwidth used:%d\n", state->used_bandwidth);
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

static void *mod_bwcap_create_server_config(apr_pool_t *p, server_rec *s)
{
    modbwcap_config *cfg=
        (modbwcap_config*)apr_pcalloc(p, sizeof(modbwcap_config));
    cfg->bandwidth_cap = 0;
    cfg->scoreboard = NULL;
    cfg->p = p;
    
    return cfg;
}

/*
 * Happens after finished configuring.  Allocates the shared memory for state.
 */
static apr_status_t mod_bwcap_post_config(apr_pool_t *p, apr_pool_t *plog,
    apr_pool_t *ptmp, server_rec *s)
{
    apr_shm_t *mem=NULL;
    modbwcap_state *state=NULL;
    modbwcap_config *cfg = ap_get_module_config(s->module_config,
        &mod_bwcap_module);

    apr_shm_create(&mem, sizeof(modbwcap_state), cfg->scoreboard, cfg->p);
    state = (modbwcap_state*)apr_shm_baseaddr_get(mem);
    state->used_bandwidth=0;
    
    fprintf(stderr,"Here%x\n",state);
    fflush(stderr);
    
    return OK;
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

/*
 * Registers hooks and filters to httpd.
 */
static void mod_bwcap_register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mod_bwcap_post_config, NULL, NULL, APR_HOOK_FIRST);
    ap_register_output_filter("mod_bwcap", mod_bwcap_filter, NULL, AP_FTYPE_TRANSCODE);
    ap_hook_handler(mod_bwcap_method_handler, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_insert_filter(mod_bwcap_insert_filter, NULL, NULL, APR_HOOK_FIRST);
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
        set_modbwcap_scoreboard_file,
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

