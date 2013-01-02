#include <digidocpp/DDoc.h>
#include <digidocpp/Document.h>
#include <digidocpp/SignatureTM.h>
#include <digidocpp/WDoc.h>
#include <digidocpp/crypto/cert/X509Cert.h>

#include <Foundation/Foundation.h>
#include <QuickLook/QuickLook.h>

using namespace digidoc;

extern "C" {
OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview,
	CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options);
void CancelPreviewGeneration(void *thisInterface, QLPreviewRequestRef preview) {}
}

@interface NSString (Digidoc)
+ (NSString*)stdstring:(const std::string&)str;
+ (NSString*)fileSize:(unsigned long)bytes;
+ (void)parseException:(const Exception&)e result:(NSMutableString *)result;
@end

@implementation NSString (Digidoc)
+ (NSString*)stdstring:(const std::string&)str
{
	return str.empty() ? [NSString string] : [NSString stringWithUTF8String:str.c_str()];
}

+ (NSString*)fileSize:(unsigned long)bytes
{
	enum {
		kb = 1UL << 1,
		mb = 1UL << 2,
		gb = 1UL << 3
	};
	if (bytes >= gb)
		return [NSString stringWithFormat:@"%1.2f GB", float(bytes) / gb];
	if (bytes >= mb)
		return [NSString stringWithFormat:@"%1.2f MB", float(bytes) / mb];
	if (bytes >= kb)
		return [NSString stringWithFormat:@"%1.1f KB", float(bytes) / kb];
	return [NSString stringWithFormat:@"%lu bytes", bytes];
}

+ (void)parseException:(const Exception&)e result:(NSMutableString *)result
{
	[result appendFormat:@"<br />%@", [self stdstring:e.getMsg()]];
	for( Exception::Causes::const_iterator i = e.getCauses().begin(); i != e.getCauses().end(); ++i ) {
		[self parseException:*i result:result];
	}
}
@end



OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview,
	CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options)
{
	NSMutableString *h = [NSMutableString string];
	[h appendString:@"<html><head><style>"];
	[h appendString:@"* { font-family: 'Lucida Sans Unicode', 'Lucida Grande', sans-serif }"];
	[h appendString:@"body { font-size: 10pt }"];
	[h appendFormat:@"h2 { padding-left: 50px; background: url(cid:%@.icns); background-size: 42px 42px; background-repeat:no-repeat; }", [(__bridge NSURL*)url pathExtension]];
	[h appendString:@"font, dt { color: #808080 }"];
	[h appendString:@"dt { float: left; clear: left; margin-left: 30px; margin-right: 10px }"];
	[h appendString:@"dl { margin-bottom: 10px }"];
	[h appendString:@"</style></head><body>"];
	[h appendFormat:@"<h2>%@<hr size='1' /></h2>", [(__bridge NSURL*)url lastPathComponent]];
	try
	{
		digidoc::initialize();
		WDoc d( [[(__bridge NSURL*)url path] UTF8String] );

		[h appendString:@"<font>Files</font><ol>"];
		for (unsigned int i = 0; i < d.documentCount(); ++i) {
			const Document doc = d.getDocument(i);
			[h appendFormat:@"<li>%@</li>", [NSString stdstring:doc.getFileName()]];
		}
		[h appendString:@"</ol>"];

		[h appendString:@"<font>Signatures</font>"];
		for (unsigned int i = 0; i < d.signatureCount(); ++i) {
			const Signature *s = d.getSignature(i);

			X509Cert ocsp;
			NSString *date;
			switch( d.documentType() )
			{
				case ADoc::DDocType:
				{
					const SignatureDDOC *ddoc = static_cast<const SignatureDDOC*>(s);
					date = [NSString stdstring:ddoc->getProducedAt()];
					ocsp = ddoc->getOCSPCertificate();
					break;
				}
				case ADoc::BDocType:
					if (s->getMediaType() == SignatureTM::MEDIA_TYPE) {
						const SignatureTM *tm = static_cast<const SignatureTM*>(s);
						date = [NSString stdstring:tm->getProducedAt()];
						ocsp = tm->getOCSPCertificate();
						break;
					}
				default:
					date = [NSString stdstring:s->getSigningTime()];
			}

			X509Cert cert = s->getSigningCertificate();
			X509Cert::Type t = cert.type();
			std::string name;
			if (t & X509Cert::TempelType) {
				name = cert.getSubjectName("CN");
			} else {
				name = cert.getSubjectName("GN") + " " + cert.getSubjectName("SN");
			}
			name += " " + cert.getSubjectName("serialNumber");
			if (t & X509Cert::TestType || ocsp.type() & X509Cert::TestType) {
				name += " (TEST)";
			}
			[h appendFormat:@"<dl><dt>Signer</dt><dd>%@</dd>", [NSString stdstring:name]];

			[date stringByReplacingOccurrencesOfString:@"Z" withString:@"-0000"];
			NSDateFormatter *df = [[NSDateFormatter alloc] init];
			[df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZ"];
			NSDate *formateddate = [df dateFromString:date];
			[df setTimeZone: [NSTimeZone defaultTimeZone]];
			[df setDateFormat:@"YYYY-MM-dd HH:mm:ss z"];
			[h appendFormat:@"<dt>Time</dt><dd>%@</dd>", [df stringFromDate:formateddate]];

			bool valid = false;
			try {
				s->validateOffline();
				valid = true;
			} catch (const Exception &) {
			}
			[h appendFormat:@"<dt>Validity</dt><dd>Signature is %@</dd>", valid ? @"valid" : @"not valid"];

			SignerRole roles = s->getSignerRole();
			if (!roles.isEmpty()) {
				NSMutableArray *array = [NSMutableArray array];
				for (std::vector<std::string>::const_iterator i = roles.claimedRoles.begin(); i != roles.claimedRoles.end(); ++i) {
					if( !i->empty() ) {
						[array addObject:[NSString stdstring:*i]];
					}
				}
				if( [array count] > 0 ) {
					[h appendFormat:@"<dt>Role</dt><dd>%@</dd>", [array componentsJoinedByString:@" / "]];
				}
			}
			SignatureProductionPlace place = s->getProductionPlace();
			if (!place.countryName.empty()) {
				[h appendFormat:@"<dt>Country</dt><dd>%@</dd>", [NSString stdstring:place.countryName]];
			}
			if (!place.city.empty()) {
				[h appendFormat:@"<dt>City</dt><dd>%@</dd>", [NSString stdstring:place.city]];
			}
			if (!place.stateOrProvince.empty()) {
				[h appendFormat:@"<dt>State</dt><dd>%@</dd>", [NSString stdstring:place.stateOrProvince]];
			}
			if (!place.postalCode.empty()) {
				[h appendFormat:@"<dt>Postal code</dt><dd>%@</dd>", [NSString stdstring:place.postalCode]];
			}
			[h appendString:@"</dl>"];
		}
		digidoc::terminate();
	} catch (const Exception &e) {
		NSMutableString *err = [NSMutableString string];
		[NSString parseException:e result:err];
		[h appendFormat:@"Failed to load document:%@", err];
	}
	[h appendString:@"</body></html>"];

	NSBundle *bundle = [NSBundle bundleWithIdentifier:@"ee.ria.DigiDocQL"];
	NSString *bimage = [bundle pathForResource:@"bdoc" ofType:@"icns"];
	NSString *dimage = [bundle pathForResource:@"ddoc" ofType:@"icns"];
	NSDictionary *bimgProps = [NSDictionary
		dictionaryWithObjects:[NSArray arrayWithObjects:
				@"image/icns",
				[NSData dataWithContentsOfFile:bimage], nil]
		forKeys:[NSArray arrayWithObjects:
				(__bridge NSString *)kQLPreviewPropertyMIMETypeKey,
				(__bridge NSString *)kQLPreviewPropertyAttachmentDataKey, nil]];
	NSDictionary *dimgProps = [NSDictionary
		dictionaryWithObjects:[NSArray arrayWithObjects:
				@"image/icns",
				[NSData dataWithContentsOfFile:dimage], nil]
		forKeys:[NSArray arrayWithObjects:
				(__bridge NSString *)kQLPreviewPropertyMIMETypeKey,
				(__bridge NSString *)kQLPreviewPropertyAttachmentDataKey, nil]];
	NSDictionary *props = [NSDictionary
		dictionaryWithObjects:[NSArray arrayWithObjects:
				@"UTF-8",
				@"text/html",
				[[bundle infoDictionary] valueForKey:@"QLPreviewWidth"],
				[[bundle infoDictionary] valueForKey:@"QLPreviewHeight"],
				[NSDictionary dictionaryWithObjects:[NSArray arrayWithObjects:dimgProps, bimgProps, nil]
											forKeys:[NSArray arrayWithObjects:@"bdoc.icns", @"ddoc.icns", nil]], nil]
		forKeys:[NSArray arrayWithObjects:
				(__bridge NSString *)kQLPreviewPropertyTextEncodingNameKey,
				(__bridge NSString *)kQLPreviewPropertyMIMETypeKey,
				(__bridge NSString *)kQLPreviewPropertyWidthKey,
				(__bridge NSString *)kQLPreviewPropertyHeightKey,
				(__bridge NSString *)kQLPreviewPropertyAttachmentsKey, nil]];
	QLPreviewRequestSetDataRepresentation(preview,
		(__bridge CFDataRef)[h dataUsingEncoding:NSUTF8StringEncoding], kUTTypeHTML, (__bridge CFDictionaryRef)props);
	return noErr;
}
