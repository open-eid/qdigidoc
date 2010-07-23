#define MAJOR_VER	0
#define MINOR_VER	1
#define RELEASE_VER	0

#ifndef BUILD_VER
#define BUILD_VER	0
#endif

#define FILE_VER	MAJOR_VER,MINOR_VER,RELEASE_VER,BUILD_VER
#define FILE_VER_DOT	MAJOR_VER.MINOR_VER.RELEASE_VER.BUILD_VER
#define VER_STR_HELPER(x)	#x
#define VER_STR(x)	VER_STR_HELPER(x)

#define ORG "Estonian ID Card"
#define APP "DigiDoc klient"
#define DOMAINURL "eesti.ee"
