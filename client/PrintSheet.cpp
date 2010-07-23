/*
 * QDigiDocCrypt
 *
 * Copyright (C) 2009 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009 Raul Metsma <raul@innovaatik.ee>
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

#include "PrintSheet.h"

#include "DigiDoc.h"
#include "common/Common.h"
#include "common/SslCertificate.h"

#include <digidocpp/Document.h>

#include <QDateTime>
#include <QFileInfo>
#include <QTextStream>

/* Workaround Ticket #540
 * tables dont accept css "word-wrap: wrap-word" instead insert spaces
 */
static QString splitWord( const QString &in )
{
	QString out;
	int lastPos = 0;
	for( int i = 0; i < in.size(); ++i )
	{
		if( !in[i].isLetterOrNumber() )
		{
			out += in.mid( lastPos, i - lastPos );
			lastPos = i;
		}
		else if( i - lastPos > 50 )
		{
			out += in.mid( lastPos, i - lastPos ) + ' ';
			lastPos = i;
		}
	}
	out += in.mid( lastPos );
	return out;
}

PrintSheet::PrintSheet( DigiDoc *d, QWidget *parent )
:	QWebView( parent )
{
	QString html;
	QTextStream s( &html );
	s
	<< "<html>"
	<< "<head>"

	<< "<style type=\"text/css\">"
	<< "#head {"
	<< "font-family: Arial, Helvetica, sans-serif;"
	<< "font-size: 28px;"
	<< "border-bottom: 2px solid #000000;"
	<< "margin-top: 10px;"
	<< "}"
	<< ".sectionHead {"
	<< "font-family: Arial, Helvetica, sans-serif;"
	<< "font-size: 18px;"
	<< "border-bottom: 1px dashed #000000;"
	<< "margin-top: 20px;"
	<< "}"
	<< "TABLE { width: 100%; margin-top: 5px; }"
	<< ".label { font-size: 11px; padding: 2px; margin-top: 5px; }"
	<< ".text, .textborder, .textborderright "
	<< "{ font-size: 12px; padding: 3px; word-wrap: break-word; vertical-align: text-top; }"
	<< ".textborder, .textborderright { border: 1px solid #000000; font-weight: bold; }"
	<< ".textborderright { border-left: 0px; }"
	<< "</style>"

	<< "</head>"
	<< "<body>"

	<< "<div id=\"head\">" << tr("VALIDITY CONFIRMATION SHEET") << "</div>"
	<< "<div class=\"sectionHead\">" << tr("SIGNED FILES") << "</div>"

	<< "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">"
	<< "<tr>"
	<< "<td class=\"label\" width=\"300\">" << tr("FILE NAME") << "</td>"
	//<< "<td class=\"label\" width=\"200\">" << tr("FILE TYPE") << "</td>"
	<< "<td class=\"label\" width=\"100\">" << tr("FILE SIZE") << "</td>"
	<< "</tr>";
	Q_FOREACH( const digidoc::Document &doc, d->documents() )
	{
		QFileInfo f( QString::fromUtf8( doc.getPath().data() ) );
		s
		<< "<tr>"
		<< "<td class=\"textborder\">" << f.fileName() << "</td>"
		//<< "<td class=\"textborderright\">" << QString::fromUtf8( doc.getMediaType().data() ) << "</td>"
		<< "<td class=\"textborderright\">" << Common::fileSize( f.size() ) << "</td>"
		<< "</tr>";
	}

	s
	<< "</table>"

	<< "<div class=\"sectionHead\">" << tr("SIGNERS") << "</div>";

	int i = 1;
	Q_FOREACH( DigiDocSignature sig, d->signatures() )
	{
		const SslCertificate cert = sig.cert();
		bool tempel = cert.isTempel();
		s
		<< "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">"
		<< "<tr>"
		<< "<td class=\"label\" width=\"40\">" << tr("NO.") << "</td>"
		<< "<td class=\"label\">" << (tempel ? tr("COMPANY") : tr("NAME")) << "</td>"
		<< "<td class=\"label\" width=\"200\">" << (tempel ? tr("REGISTER CODE") : tr("PERSONAL CODE")) << "</td>"
		<< "<td class=\"label\" width=\"160\">" << tr("TIME") << "</td>"
		<< "</tr>"
		<< "<tr>"
		<< "<td class=\"textborder\">" << i << "</td>"
		<< "<td class=\"textborderright\">" << cert.toString( tempel ? "CN" : "GN SN" ) << "</td>"
		<< "<td class=\"textborderright\">" << cert.subjectInfo( "serialNumber" ) << "</td>"
		<< "<td class=\"textborderright\">" << sig.dateTime().toString( "dd.MM.yyyy hh:mm:ss" ) << "</td>"
		<< "</tr>"
		<< "</table>"

		<< "<div class=\"label\">" << tr("VALIDITY OF SIGNATURE") << "</div>"
		<< "<div class=\"textborder\">" << tr("SIGNATURE") << " ";
		switch( sig.validate() )
		{
		case DigiDocSignature::Valid: s << tr("VALID"); break;
		case DigiDocSignature::Invalid: s << tr("NOT VALID"); break;
		case DigiDocSignature::Unknown: s << tr("UNKNOWN"); break;
		}
		s << "</div>"

		<< "<div class=\"label\">" << tr("ROLE / RESOLUTION") << "</div>"
		<< "<div class=\"textborder\">" << sig.role() << "&nbsp;</div>"

		<< "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">"
		<< "<tr>"
		<< "<td class=\"label\">" << tr("PLACE OF CONFIRMATION (CITY, STATE, ZIP, COUNTRY)") << "</td>"
		<< "<td class=\"label\" width=\"200\">" << tr("SERIAL NUMBER OF CERTIFICATE") << "</td>"
		<< "</tr>"
		<< "<td class=\"textborder\">" << splitWord( sig.location() ) << "&nbsp;</td>"
		<< "<td class=\"textborderright\">" << cert.serialNumber() << "&nbsp;</td>"
		<< "</table>"

		<< "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">"
		<< "<tr>"
		<< "<td class=\"label\" width=\"185\">" << tr("ISSUER OF CERTIFICATE") << "</td>"
		<< "<td class=\"label\">" << tr("HASH VALUE OF ISSUER'S PUBLIC KEY") << "</td>"
		<< "</tr>"
		<< "<td class=\"textborder\">" << cert.issuerInfo( QSslCertificate::CommonName ) << "</td>"
		<< "<td class=\"textborderright\">" << cert.toHex( cert.authorityKeyIdentifier() ) << "</td>"
		<< "</table>"

		<< "<div class=\"label\">" << tr("HASH VALUE OF VALIDITY CONFIRMATION (OCSP RESPONSE)") << "</div>"
		<< "<div class=\"textborder\">" << cert.toHex( sig.digestValue() ) << "&nbsp;</div>";

		++i;
	}

	s
	<< "<div class=\"text\" style=\"margin-top: 10px\">"
	<< tr("The print out of files listed in the section <b>\"Signed Files\"</b> "
		  "are inseparable part of this Validity Confirmation Sheet.")
	<< "</div>"
	<< "<div class=\"label\" style=\"margin-top: 20px\">" << tr("NOTES") << "</div>"
	<< "<div class=\"textborder\" style=\"height: 100px\"></div>"
	<< "</body>"
	<< "</html>";

	setHtml( html );
}
