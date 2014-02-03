/*
 * QEstEidClient
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <digidocpp/Container.h>
#include <digidocpp/DataFile.h>
#include <digidocpp/Signature.h>
#include <digidocpp/Exception.h>
#include <digidocpp/crypto/X509Cert.h>

#include <Foundation/Foundation.h>
#include <QuickLook/QuickLook.h>

using namespace digidoc;

enum Type
{
	UnknownType = 0,
	DigiIDType = 1,
	EstEidType = 2,
	MobileIDType = 4,
	OCSPType = 8,
	TempelType = 16,

	TestType = 32,
	DigiIDTestType = TestType|DigiIDType,
	EstEidTestType = TestType|EstEidType,
	MobileIDTestType = TestType|MobileIDType,
	OCSPTestType = TestType|OCSPType,
	TempelTestType = TestType|TempelType
};

static Type type(const X509Cert &cert, bool ocsp)
{
	for( const std::string &pol : cert.certificatePolicies() )
	{
		if(ocsp)
		{
			return pol.compare(0, 20, "1.3.6.1.4.1.10015.3.") == 0 ||
				cert.subjectName("CN").find("TEST") != std::string::npos ?
				OCSPTestType : OCSPType;
		}

		if(pol.compare(0, 22, "1.3.6.1.4.1.10015.1.1.") == 0)
			return EstEidType;
		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.1.2.") == 0)
			return DigiIDType;
		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.1.3.") == 0 ||
			pol.compare(0, 23, "1.3.6.1.4.1.10015.11.1.") == 0)
			return MobileIDType;

		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.3.1.") == 0)
			return EstEidTestType;
		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.3.2.") == 0)
			return DigiIDTestType;
		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.3.3.") == 0 ||
			pol.compare(0, 23, "1.3.6.1.4.1.10015.11.3.") == 0)
			return MobileIDTestType;
		else if(pol.compare(0, 22, "1.3.6.1.4.1.10015.3.7.") == 0 ||
			(pol.compare(0, 20, "1.3.6.1.4.1.10015.7.") == 0 &&
			cert.issuerName("CN").find("TEST") != std::string::npos) )
			return TempelTestType;

		else if(pol.compare(0, 20, "1.3.6.1.4.1.10015.7.") == 0)
			return TempelType;
	}

	return UnknownType;
}

extern "C" {
OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview,
	CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options);
void CancelPreviewGeneration(void * /*thisInterface*/, QLPreviewRequestRef /*preview*/) {}
}

@interface NSString (Digidoc)
+ (NSString*)stdstring:(const std::string&)str;
+ (NSString*)fileSize:(unsigned long)bytes;
+ (void)parseException:(const Exception&)e result:(NSMutableArray *)result;
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

+ (void)parseException:(const Exception&)e result:(NSMutableArray *)result
{
	[result addObject:[self stdstring:e.msg()]];
	for( const Exception &i : e.causes() ) {
		[self parseException:i result:result];
	}
}
@end



OSStatus GeneratePreviewForURL(void */*thisInterface*/, QLPreviewRequestRef preview,
	CFURLRef url, CFStringRef /*contentTypeUTI*/, CFDictionaryRef /*options*/)
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
		Container d( [[(__bridge NSURL*)url path] UTF8String] );

		[h appendString:@"<font>Files</font><ol>"];
		for (const DataFile &doc : d.dataFiles()) {
			[h appendFormat:@"<li>%@</li>", [NSString stdstring:doc.fileName()]];
		}
		[h appendString:@"</ol>"];

		[h appendString:@"<font>Signatures</font>"];
		for (const Signature *s : d.signatures()) {
			X509Cert cert = s->signingCertificate();
			X509Cert ocsp = s->OCSPCertificate();
			Type t = type(cert, false);
			std::string name;
			if (t & TempelType) {
				name = cert.subjectName("CN");
			} else {
				name = cert.subjectName("GN") + " " + cert.subjectName("SN");
			}
			name += " " + cert.subjectName("serialNumber");
			if (t & TestType || type(ocsp, true) & TestType) {
				name += " (TEST)";
			}
			[h appendFormat:@"<dl><dt>Signer</dt><dd>%@</dd>", [NSString stdstring:name]];

			NSString *date = [NSString stdstring:s->producedAt()];
			if ([date length] == 0) {
				date = [NSString stdstring:s->signingTime()];
			}
			[date stringByReplacingOccurrencesOfString:@"Z" withString:@"-0000"];
			NSDateFormatter *df = [[NSDateFormatter alloc] init];
			[df setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZ"];
			NSDate *formateddate = [df dateFromString:date];
			[df setTimeZone: [NSTimeZone defaultTimeZone]];
			[df setDateFormat:@"YYYY-MM-dd HH:mm:ss z"];
			[h appendFormat:@"<dt>Time</dt><dd>%@</dd>", [df stringFromDate:formateddate]];

			bool valid = false;
			try {
				s->validate();
				valid = true;
			} catch (const Exception &) {
			}
			[h appendFormat:@"<dt>Validity</dt><dd>Signature is %@</dd>", valid ? @"valid" : @"not valid"];

			NSMutableArray *roles = [NSMutableArray array];
			for (const std::string &role : s->signerRoles()) {
				if( !role.empty() ) {
					[roles addObject:[NSString stdstring:role]];
				}
			}
			if( [roles count] > 0 ) {
				[h appendFormat:@"<dt>Role</dt><dd>%@&nbsp;</dd>", [roles componentsJoinedByString:@" / "]];
			}
			if (!s->countryName().empty()) {
				[h appendFormat:@"<dt>Country</dt><dd>%@&nbsp;</dd>", [NSString stdstring:s->countryName()]];
			}
			if (!s->city().empty()) {
				[h appendFormat:@"<dt>City</dt><dd>%@&nbsp;</dd>", [NSString stdstring:s->city()]];
			}
			if (!s->stateOrProvince().empty()) {
				[h appendFormat:@"<dt>State</dt><dd>%@&nbsp;</dd>", [NSString stdstring:s->stateOrProvince()]];
			}
			if (!s->postalCode().empty()) {
				[h appendFormat:@"<dt>Postal code</dt><dd>%@&nbsp;</dd>", [NSString stdstring:s->postalCode()]];
			}
			[h appendString:@"</dl>"];
		}
		digidoc::terminate();
	} catch (const Exception &e) {
		NSMutableArray *err = [NSMutableArray array];
		[NSString parseException:e result:err];
		[h appendFormat:@"Failed to load document:<br />%@", [err componentsJoinedByString:@"<br />"]];
	}
	[h appendString:@"</body></html>"];

	NSBundle *bundle = [NSBundle bundleWithIdentifier:@"ee.ria.DigiDocQL"];
	NSString *bimage = [bundle pathForResource:@"bdoc" ofType:@"icns"];
	NSString *dimage = [bundle pathForResource:@"ddoc" ofType:@"icns"];
	NSDictionary *bimgProps = @{
		(__bridge NSString *)kQLPreviewPropertyMIMETypeKey : @"image/icns",
		(__bridge NSString *)kQLPreviewPropertyAttachmentDataKey : [NSData dataWithContentsOfFile:bimage] };
	NSDictionary *dimgProps = @{
		(__bridge NSString *)kQLPreviewPropertyMIMETypeKey : @"image/icns",
		(__bridge NSString *)kQLPreviewPropertyAttachmentDataKey : [NSData dataWithContentsOfFile:dimage] };
	NSDictionary *props = @{
		(__bridge NSString *)kQLPreviewPropertyTextEncodingNameKey : @"UTF-8",
		(__bridge NSString *)kQLPreviewPropertyMIMETypeKey : @"text/html",
		(__bridge NSString *)kQLPreviewPropertyWidthKey : [[bundle infoDictionary] valueForKey:@"QLPreviewWidth"],
		(__bridge NSString *)kQLPreviewPropertyHeightKey : [[bundle infoDictionary] valueForKey:@"QLPreviewHeight"],
		(__bridge NSString *)kQLPreviewPropertyAttachmentsKey : @{ @"bdoc.icns" : dimgProps, @"ddoc.icns" : bimgProps } };
	QLPreviewRequestSetDataRepresentation(preview,
		(__bridge CFDataRef)[h dataUsingEncoding:NSUTF8StringEncoding], kUTTypeHTML, (__bridge CFDictionaryRef)props);
	return noErr;
}
