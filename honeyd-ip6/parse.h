/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CREATE = 258,
     ADD = 259,
     PORT = 260,
     BIND = 261,
     CLONE = 262,
     DOT = 263,
     BLOCK = 264,
     OPEN = 265,
     RESET = 266,
     DEFAULT = 267,
     SET = 268,
     ACTION = 269,
     PERSONALITY = 270,
     RANDOM = 271,
     ANNOTATE = 272,
     NO = 273,
     FINSCAN = 274,
     FRAGMENT = 275,
     DROP = 276,
     OLD = 277,
     NEW = 278,
     COLON = 279,
     PROXY = 280,
     UPTIME = 281,
     DROPRATE = 282,
     IN = 283,
     SYN = 284,
     UID = 285,
     GID = 286,
     ROUTE = 287,
     ENTRY = 288,
     LINK = 289,
     NET = 290,
     UNREACH = 291,
     SLASH = 292,
     LATENCY = 293,
     MS = 294,
     LOSS = 295,
     BANDWIDTH = 296,
     SUBSYSTEM = 297,
     OPTION = 298,
     TO = 299,
     SHARED = 300,
     NETWORK = 301,
     SPOOF = 302,
     FROM = 303,
     TEMPLATE = 304,
     OBRACKET = 305,
     CBRACKET = 306,
     RBRACKET = 307,
     LBRACKET = 308,
     TUNNEL = 309,
     TARPIT = 310,
     DYNAMIC = 311,
     USE = 312,
     IF = 313,
     OTHERWISE = 314,
     EQUAL = 315,
     SOURCE = 316,
     OS = 317,
     IP = 318,
     BETWEEN = 319,
     DELETE = 320,
     LIST = 321,
     ETHERNET = 322,
     DHCP = 323,
     ON = 324,
     MAXFDS = 325,
     RESTART = 326,
     DEBUG = 327,
     DASH = 328,
     TIME = 329,
     INTERNAL = 330,
     RANDOMIPVS = 331,
     RANDOMEXCLUDE = 332,
     SUBMISSION = 333,
     STRING = 334,
     CMDSTRING = 335,
     IPSTRING = 336,
     IPSSTRING = 337,
     FILENAMESTRING = 338,
     YESNO = 339,
     NUMBER = 340,
     LONG = 341,
     PROTO = 342,
     FLOAT = 343
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define PORT 260
#define BIND 261
#define CLONE 262
#define DOT 263
#define BLOCK 264
#define OPEN 265
#define RESET 266
#define DEFAULT 267
#define SET 268
#define ACTION 269
#define PERSONALITY 270
#define RANDOM 271
#define ANNOTATE 272
#define NO 273
#define FINSCAN 274
#define FRAGMENT 275
#define DROP 276
#define OLD 277
#define NEW 278
#define COLON 279
#define PROXY 280
#define UPTIME 281
#define DROPRATE 282
#define IN 283
#define SYN 284
#define UID 285
#define GID 286
#define ROUTE 287
#define ENTRY 288
#define LINK 289
#define NET 290
#define UNREACH 291
#define SLASH 292
#define LATENCY 293
#define MS 294
#define LOSS 295
#define BANDWIDTH 296
#define SUBSYSTEM 297
#define OPTION 298
#define TO 299
#define SHARED 300
#define NETWORK 301
#define SPOOF 302
#define FROM 303
#define TEMPLATE 304
#define OBRACKET 305
#define CBRACKET 306
#define RBRACKET 307
#define LBRACKET 308
#define TUNNEL 309
#define TARPIT 310
#define DYNAMIC 311
#define USE 312
#define IF 313
#define OTHERWISE 314
#define EQUAL 315
#define SOURCE 316
#define OS 317
#define IP 318
#define BETWEEN 319
#define DELETE 320
#define LIST 321
#define ETHERNET 322
#define DHCP 323
#define ON 324
#define MAXFDS 325
#define RESTART 326
#define DEBUG 327
#define DASH 328
#define TIME 329
#define INTERNAL 330
#define RANDOMIPVS 331
#define RANDOMEXCLUDE 332
#define SUBMISSION 333
#define STRING 334
#define CMDSTRING 335
#define IPSTRING 336
#define IPSSTRING 337
#define FILENAMESTRING 338
#define YESNO 339
#define NUMBER 340
#define LONG 341
#define PROTO 342
#define FLOAT 343




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 154 "parse.y"

	char *string;
	int number;
	unsigned long long longvalue;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality_set *pers;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;



/* Line 2068 of yacc.c  */
#line 245 "parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


