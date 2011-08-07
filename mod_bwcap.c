#include <assert.h>
#include "httpd.h"
#include "http_config.h"
#include "util_filter.h"
#include "apr_global_mutex.h"

module AP_MODULE_DECLARE_DATA mod_bwcap_module;

typedef struct {
    /*The number of bytes to send before sending 503s.*/
    long long bandwidth_cap;
    /*Path to file where we should store the amount of data sent.*/
    char *scoreboard;
    /*The pool used to create the shared memory.*/
    apr_pool_t *p;
    /*The mutex used to control access to the scoreboard.*/
    apr_global_mutex_t *scoreboard_mutex;
} modbwcap_config;

typedef struct {
    /*The number of bytes sent so far.*/
    long long used_bandwidth;
} modbwcap_state;

/*
 * Reads the state stored in the file, writes back the updates, and closes the
 * file.
 *
 * Although this function will work on any endian, it is not portable between
 * endianness (you can't move the written file to a machine with a different
 * endianness).
 *
 * Returns the total number of bytes used.
 */
static long long mod_bwcap_update_state(long long bytes_sent, modbwcap_config *cfg)
{
    modbwcap_state state;
    state.used_bandwidth = 0;
    FILE *f;
    
    assert(bytes_sent >= 0);
    
    apr_global_mutex_lock(cfg->scoreboard_mutex);
    f = fopen(cfg->scoreboard, "r");
    if(f)
    {
        fread(&state, sizeof(modbwcap_state), 1, f);
        state.used_bandwidth += bytes_sent;
        fclose(f);
    }
    /*Optimization.  Only write if something has changed.*/
    if (bytes_sent > 0)
    {
        f = fopen(cfg->scoreboard, "w");
        fwrite(&state, sizeof(modbwcap_state), 1, f);
        fclose(f);        
    }
    apr_global_mutex_unlock(cfg->scoreboard_mutex);
    return state.used_bandwidth;
}

/*
 * Handles counting the number of bytes.
 */
static int mod_bwcap_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    apr_status_t rv;
    
    modbwcap_config *cfg = ap_get_module_config(f->r->server->module_config,
        &mod_bwcap_module);
    
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

    mod_bwcap_update_state(bucket_size, cfg);
    
    return ap_pass_brigade(f->next, bb);
}

/*
 * Handles the request by registering the filter that counts bytes.
 * Also cancelles the request if the number of bytes is exceeded.
 */
static int mod_bwcap_method_handler (request_rec *r)
{
    modbwcap_config *cfg = ap_get_module_config(r->server->module_config,
        &mod_bwcap_module);

    long long used_bandwidth = mod_bwcap_update_state(0, cfg);
    
    if (used_bandwidth > cfg->bandwidth_cap)
        return 503;
    else
        return DECLINED;
}

/*
 * Called to insert the filter that counts the number of bytes.
 */
static int mod_bwcap_insert_filter(request_rec *r)
{
    ap_add_output_filter("mod_bwcap", NULL, r, r->connection);
    return OK;
}

static void *mod_bwcap_create_server_config(apr_pool_t *p, server_rec *s)
{
    modbwcap_config *cfg=
        (modbwcap_config*)apr_pcalloc(p, sizeof(modbwcap_config));
    cfg->bandwidth_cap = 0;
    cfg->scoreboard = "scoreboard";
    cfg->p = p;
    
    return cfg;
}

/*
 * Happens after finished configuring.  Allocates the shared memory for state.
 */
static apr_status_t mod_bwcap_post_config(apr_pool_t *p, apr_pool_t *plog,
    apr_pool_t *ptmp, server_rec *s)
{
    FILE *f;
    modbwcap_config *cfg = ap_get_module_config(s->module_config,
        &mod_bwcap_module);
        
    apr_global_mutex_create(&cfg->scoreboard_mutex,
        "mod_bwcap_scoreboard_mutex", APR_LOCK_DEFAULT, cfg->p);

    return OK;
}

static const char *set_modbwcap_bandwidth_cap(cmd_parms *params, void *mconfig,
    const char *arg)
{
    modbwcap_config *cfg = ap_get_module_config(params->server->module_config,
        &mod_bwcap_module);
    cfg->bandwidth_cap = atol(arg);

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

