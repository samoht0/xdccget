#include <argp.h>
#include <strings.h>
#include <stdlib.h>
#include "helper.h"

#include "argument_parser.h"


const char *argp_program_version = "xdccget 1.0";
const char *argp_program_bug_address ="<nobody@nobody.org>";

/* Program documentation. */
static char doc[] =
"xdccget -- download from cmd with xdcc";

/* A description of the arguments we accept. */
static char args_doc[] = "<server> <channel(s)> <bot cmds>";

#define OPT_ACCEPT_ALL_NICKS 1
#define OPT_DONT_CONFIRM_OFFSETS 2


/* The options we understand. */
static struct argp_option options[] = {
{"verbose",  'v', 0,      0,  "Produce verbose output", 0 },
{"quiet",    'q', 0,      0,  "Don't produce any output", 0 },
{"information",    'i', 0,      0,  "Produce information output.", 0 },
{"checksum-verify", 'c', 0,      0,  "Stay connected after download completed to verify checksums.", 0 },
{"ipv4",   '4', 0,      0,  "Use ipv4 to connect to irc server.", 0 },
#ifdef ENABLE_IPV6
{"ipv6",   '6', 0,      0,  "Use ipv6 to connect to irc server.", 0 },
#endif
{"port",   'p', "<port number>",      0,  "Use the following port to connect to server. default is 6667.", 0 },
{"directory",   'd', "<download-directory>",      0,  "Directory, where to place the files." , 0 },
{"nick",   'n', "<nickname>",      0,  "Use this specific nickname while connecting to the irc-server.", 0 },
{"login",   'l', "<login-command>",      0,  "Use this login-command to authorize your nick to the irc-server after connecting.", 0 },
{"accept-all-nicks",   OPT_ACCEPT_ALL_NICKS, 0,      0,  "Accept DCC send requests from ALL bots and do not verify any nicknames of incoming dcc requests.", 0 },
{"dont-confirm-offsets",   OPT_DONT_CONFIRM_OFFSETS, 0,      0,  "Do not send file offsets to the bots. Can be used on bots where the transfer gets stucked after a short while.", 0 },
{ 0 }
};

static error_t parse_opt (int key, char *arg, struct argp_state *state);

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc, NULL, NULL, NULL };

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    /* Get the input argument from argp_parse, which we
      know is a pointer to our arguments structure. */
    struct xdccGetConfig *cfg = state->input;

    switch (key) {
    case 'q':
        DBG_OK("setting log-level as quiet.");
        cfg->logLevel = LOG_QUIET;
        break;

    case 'v':
        DBG_OK("setting log-level as warn.");
        cfg->logLevel = LOG_WARN;
        break;

    case 'i':
        DBG_OK("setting log-level as info.");
        cfg->logLevel = LOG_INFO;
        break;
        
    case 'c':
        DBG_OK("setting verify checksum option.");
        cfg_set_bit(cfg, VERIFY_CHECKSUM_FLAG);
        break;

    case 'd':
        DBG_OK("setting target dir as %s", arg);
        cfg->targetDir = sdsnew(arg);
        break;
        
    case 'n':
        DBG_OK("setting nickname as %s", arg);
        cfg->nick = sdsnew(arg);
        break;
        
    case 'l':
         DBG_OK("setting login-command as %s", arg);
        cfg->login_command = sdsnew(arg);
        break;

    case 'p':
        cfg->port = (unsigned short) strtoul(arg, NULL, 0);
        DBG_OK("setting port as %u", cfg->port);
        break;
	
    case OPT_ACCEPT_ALL_NICKS:
        cfg_set_bit(cfg, ACCEPT_ALL_NICKS_FLAG);
        break;
    case OPT_DONT_CONFIRM_OFFSETS:
	    cfg_set_bit(cfg, DONT_CONFIRM_OFFSETS_FLAG);
	    break;
    case '4':
        cfg_set_bit(cfg, USE_IPV4_FLAG);
        break;

#ifdef ENABLE_IPV6
    case '6':
        cfg_set_bit(cfg, USE_IPV6_FLAG);
        break;
#endif

    case ARGP_KEY_ARG:
    {
        if (state->arg_num >= 3)
            /* Too many arguments. */
            argp_usage(state);

        cfg->args[state->arg_num] = arg;
    }
        break;

    case ARGP_KEY_END:
        if (state->arg_num < 3)
            /* Not enough arguments. */
            argp_usage(state);
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void parseArguments(int argc, char **argv, struct xdccGetConfig *cfg) {
    /* Parse our arguments; every option seen by parse_opt will
      be reflected in arguments. */
    int ret = argp_parse(&argp, argc, argv, 0, 0, cfg);

	if (ret != 0) {
		logprintf(LOG_ERR, "the parsing of the command line options failed");
	}
}

struct dccDownload* newDccDownload(sds botNick, sds xdccCmd) {
    struct dccDownload *t = (struct dccDownload*) Malloc(sizeof (struct dccDownload));
    t->botNick = botNick;
    t->xdccCmd = xdccCmd;
    return t;
}

void freeDccDownload(struct dccDownload *t) {
    sdsfree(t->botNick);
    sdsfree(t->xdccCmd);
    FREE(t);
}

struct dccDownloadProgress* newDccProgress(char *completePath, irc_dcc_size_t complFileSize) {
    struct dccDownloadProgress *t = (struct dccDownloadProgress*) Malloc(sizeof (struct dccDownloadProgress));
    t->completeFileSize = complFileSize;
    t->sizeRcvd = 0;
    t->sizeNow = 0;
    t->sizeLast = 0;
    t->completePath = completePath;
    return t;

}

void freeDccProgress(struct dccDownloadProgress *progress) {
    sdsfree(progress->completePath);
    FREE(progress);
}

void parseDccDownload(char *dccDownloadString, sds *nick, sds *xdccCmd) {
    size_t i;
    size_t strLen = strlen(dccDownloadString);
    size_t spaceFound = 0;

    for (i = 0; i < strLen; i++) {
        if (dccDownloadString[i] == ' ') {
            spaceFound = i;
            break;
        }
    }

    size_t nickLen = spaceFound + 1;
    size_t cmdLen = (strLen - spaceFound) + 1;

    DBG_OK("nickLen = %zu, cmdLen = %zu", nickLen, cmdLen);

    sds nickPtr = sdsnewlen(NULL, nickLen);
    sds xdccPtr = sdsnewlen(NULL, cmdLen);

    nickPtr = sdscpylen(nickPtr, dccDownloadString, nickLen - 1);
    xdccPtr = sdscpylen(xdccPtr, dccDownloadString + (spaceFound + 1), cmdLen - 1);

    *nick = nickPtr;
    *xdccCmd = xdccPtr;
}

sds* parseChannels(char *channelString, uint32_t *numChannels) {
    int numFound = 0;
    char *seperator = ",";
    sds *splittedString = sdssplitlen(channelString, strlen(channelString), seperator, strlen(seperator), &numFound);
    if (splittedString == NULL) {
        DBG_ERR("splittedString = NULL, cant continue from here.");
    }
    int i = 0;

    for (i = 0; i < numFound; i++) {
        sdstrim(splittedString[i], " \t");
        DBG_OK("%d: '%s'", i, splittedString[i]);
    }

    *numChannels = numFound;

    return splittedString;
}

struct dccDownload** parseDccDownloads(char *dccDownloadString, unsigned int *numDownloads) {
    int numFound = 0;
    int i = 0, j = 0;
    char *seperator = ",";

    sds *splittedString = sdssplitlen(dccDownloadString, strlen(dccDownloadString), seperator, strlen(seperator), &numFound);

    if (splittedString == NULL) {
        DBG_ERR("splittedString = NULL, cant continue from here.");
    }

    struct dccDownload **dccDownloadArray = (struct dccDownload**) Calloc(numFound + 1, sizeof (struct dccDownload*));

    *numDownloads = numFound;

    for (i = 0; i < numFound; i++) {
        sdstrim(splittedString[i], " \t");
        sds nick = NULL;
        sds xdccCmd = NULL;
        DBG_OK("%d: '%s'\n", i, splittedString[i]);
        parseDccDownload(splittedString[i], &nick, &xdccCmd);
        DBG_OK("%d: '%s' '%s'\n", i, nick, xdccCmd);
        if (nick != NULL && xdccCmd != NULL) {
            dccDownloadArray[j] = newDccDownload(nick, xdccCmd);
            j++;
        }
        else {
            if (nick != NULL)
                sdsfree(nick);

            if (xdccCmd != NULL)
                sdsfree(xdccCmd);
        }
        sdsfree(splittedString[i]);
    }

    FREE(splittedString);
    return dccDownloadArray;
}
