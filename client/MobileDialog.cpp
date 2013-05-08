/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2013 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2013 Raul Metsma <raul@innovaatik.ee>
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

#include "MobileDialog.h"

#include "AccessCert.h"
#include "Application.h"
#include "DigiDoc.h"

#include <common/Settings.h>
#include <common/SOAPDocument.h>
#include <common/SslCertificate.h>

#include <QtCore/QDir>
#include <QtCore/QTimeLine>
#include <QtCore/QTimer>
#include <QtCore/QXmlStreamReader>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkProxy>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QSslKey>
#include <QtNetwork/QSslConfiguration>

using namespace digidoc;

MobileDialog::MobileDialog( QWidget *parent )
:	QDialog( parent )
{
	mobileResults["START"] = tr("Signing in process");
	mobileResults["REQUEST_OK"] = tr("Request accepted");
	mobileResults["EXPIRED_TRANSACTION"] = tr("Request timeout");
	mobileResults["USER_CANCEL"] = tr("User denied or cancelled");
	mobileResults["SIGNATURE"] = tr("Got signature");
	mobileResults["OUTSTANDING_TRANSACTION"] = tr("Request pending");
	mobileResults["MID_NOT_READY"] = tr("Mobile-ID not ready, try again later");
	mobileResults["PHONE_ABSENT"] = tr("Phone absent");
	mobileResults["SENDING_ERROR"] = tr("Request sending error");
	mobileResults["SIM_ERROR"] = tr("SIM error");
	mobileResults["INTERNAL_ERROR"] = tr("Service internal error");
	mobileResults["OCSP_UNAUTHORIZED"] = tr("Not allowed to use OCSP service!<br/>Please check your server access sertificate.");
	mobileResults["HOSTNOTFOUND"] = tr("Connecting to SK server failed!<br/>Please check your internet connection.");
	mobileResults["User is not a Mobile-ID client"] = tr("User is not a Mobile-ID client");
	mobileResults["ID and phone number do not match"] = tr("ID and phone number do not match");
	mobileResults["Certificate status unknown"] = tr("Your Mobile-ID service is not activated.<br/>Please activate your Mobiil-ID at <a href=\"http://mobiil.id.ee/akt\">http://mobiil.id.ee/akt</a>");
	mobileResults["Certificate is revoked"] = tr("Mobile-ID user certificates are revoked or suspended.");

	setupUi( this );
	code->setBuddy( signProgressBar );

	statusTimer = new QTimeLine( signProgressBar->maximum() * 1000, this );
	statusTimer->setCurveShape( QTimeLine::LinearCurve );
	statusTimer->setFrameRange( signProgressBar->minimum(), signProgressBar->maximum() );
	connect( statusTimer, SIGNAL(frameChanged(int)), signProgressBar, SLOT(setValue(int)) );
	connect( statusTimer, SIGNAL(finished()), SLOT(endProgress()) );

	manager = new QNetworkAccessManager( this );
	connect( manager, SIGNAL(finished(QNetworkReply*)), SLOT(finished(QNetworkReply*)) );
	connect( manager, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
		SLOT(sslErrors(QNetworkReply*,QList<QSslError>)) );

	if( !Application::confValue( Application::ProxyHost ).toString().isEmpty() )
	{
		manager->setProxy( QNetworkProxy(
			QNetworkProxy::HttpProxy,
			Application::confValue( Application::ProxyHost ).toString(),
			Application::confValue( Application::ProxyPort ).toUInt(),
			Application::confValue( Application::ProxyUser ).toString(),
			Application::confValue( Application::ProxyPass ).toString() ) );
	}

	if( !Application::confValue( Application::PKCS12Disable ).toBool() )
	{
		QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
		ssl.setPrivateKey( AccessCert::key() );
		ssl.setLocalCertificate( AccessCert::cert() );
		request.setSslConfiguration( ssl );
	}

	request.setHeader( QNetworkRequest::ContentTypeHeader, "text/xml" );
	request.setRawHeader( "User-Agent", QString( "%1/%2 (%3)")
		.arg( qApp->applicationName() ).arg( qApp->applicationVersion() ).arg( Common::applicationOs() ).toUtf8() );
}

void MobileDialog::endProgress()
{ labelError->setText( mobileResults.value( "EXPIRED_TRANSACTION" ) ); }

void MobileDialog::finished( QNetworkReply *reply )
{
	switch( reply->error() )
	{
	case QNetworkReply::NoError:
	case QNetworkReply::UnknownContentError:
		break;
	case QNetworkReply::HostNotFoundError:
		labelError->setText( mobileResults.value( "HOSTNOTFOUND" ) );
		statusTimer->stop();
		reply->deleteLater();
		return;
	case QNetworkReply::SslHandshakeFailedError:
		statusTimer->stop();
		reply->deleteLater();
		return;
	default:
		labelError->setText( reply->errorString() );
		statusTimer->stop();
		reply->deleteLater();
		return;
	}

	QXmlStreamReader xml( reply );
	QString fault, message, sess, challenge, status;
	while( xml.readNext() != QXmlStreamReader::Invalid )
	{
		if( !xml.isStartElement() )
			continue;
		if( xml.name() == "faultstring" )
			fault = xml.readElementText();
		else if( xml.name() == "message" )
			message = xml.readElementText();
		else if( xml.name() == "ChallengeID" )
			challenge = xml.readElementText();
		else if( xml.name() == "Sesscode" )
			sess = xml.readElementText();
		else if( xml.name() == "Status" )
			status = xml.readElementText();
		else if( xml.name() == "Signature" )
			m_signature = xml.readElementText().toUtf8();
	}
	reply->deleteLater();

	if( !fault.isEmpty() )
	{
		labelError->setText( mobileResults.value( message, message ) );
		statusTimer->stop();
		return;
	}

	if( sessionCode.isEmpty() )
	{
		sessionCode = sess;
		if( sessionCode.isEmpty() )
		{
			labelError->setText( mobileResults.value( message ) );
			statusTimer->stop();
		}
		else
		{
			code->setText( tr("Make sure control code matches with one in phone screen\n"
				"and enter Mobile-ID PIN.\nControl code: %1").arg( challenge ) );
			code->setAccessibleName( code->text() );
		}
	}

	if( statusTimer->state() == QTimeLine::NotRunning )
		return;

	labelError->setText( mobileResults.value( status ) );
	if( status == "OK" || status == "REQUEST_OK" || status == "OUTSTANDING_TRANSACTION" )
	{
		QTimer::singleShot(5*1000, this, SLOT(sendStatusRequest()));
		return;
	}
	statusTimer->stop();
	if( status == "SIGNATURE" )
		close();
}

bool MobileDialog::isTest( const QString &ssid, const QString &cell )
{
	QString cell2 = cell.right( 8 );
	return
		(ssid == "14212128020" && cell2 == "37200002") ||
		(ssid == "14212128021" && cell2 == "37200003") ||
		(ssid == "14212128022" && cell2 == "37200004") ||
		(ssid == "14212128023" && cell2 == "37200005") ||
		(ssid == "14212128024" && cell2 == "37200006") ||
		(ssid == "14212128025" && cell2 == "37200007") ||
		(ssid == "14212128026" && cell2 == "37200008") ||
		(ssid == "14212128027" && cell2 == "37200009") ||
		(ssid == "38002240211" && cell2 == "37200001");
}

void MobileDialog::sendStatusRequest()
{
	SOAPDocument doc( "GetMobileCreateSignatureStatus", DIGIDOCSERVICE );
	doc.writeParameter( "Sesscode", sessionCode.toInt() );
	doc.writeParameter( "WaitSignature", false );
	doc.writeEndDocument();
	manager->post( request, doc.document() );
}

void MobileDialog::setSignatureInfo( const QString &city, const QString &state,
	const QString &zip, const QString &country, const QStringList &_roles )
{
	roles = _roles;
	roles.removeAll( "" );
	location = QStringList() << city << state << zip << country;
}

void MobileDialog::sign( const DigiDoc *doc, const QString &ssid, const QString &cell )
{
	QString url = isTest( ssid, cell ) ?
		"https://www.openxades.org:8443" : "https://digidocservice.sk.ee";
	request.setUrl( Settings().value( doc->documentType() == DigiDoc::BDocType ?
		"Client/bdocurl" : "Client/ddocurl", url ).toUrl() );

	labelError->setText( mobileResults.value( "START" ) );

	QHash<QString,QString> lang;
	lang["et"] = "EST";
	lang["en"] = "ENG";
	lang["ru"] = "RUS";

	SOAPDocument r( "MobileCreateSignature", DIGIDOCSERVICE );
	r.writeParameter( "IDCode", ssid );
	r.writeParameter( "PhoneNo", "+" + cell );
	r.writeParameter( "Language", lang.value( Settings::language(), "EST" ) );
	r.writeParameter( "ServiceName", "DigiDoc3" );
	QString title =  tr("Sign") + " " + QFileInfo( doc->fileName() ).fileName();
	if( title.size() > 39 )
	{
		title.resize( 36 );
		title += "...";
	}
	r.writeParameter( "MessageToDisplay", title + "\n" );
	r.writeParameter( "City", location.value(0) );
	r.writeParameter( "StateOrProvince", location.value(1) );
	r.writeParameter( "PostalCode", location.value(2) );
	r.writeParameter( "CountryName", location.value(3) );
	r.writeParameter( "Role", roles.join(" / ") );
	r.writeParameter( "SigningProfile", "" );

	r.writeStartElement( "DataFiles" );
	r.writeAttribute( XML_SCHEMA_INSTANCE, "type", "m:DataFileDigestList" );
	DocumentModel *m = doc->documentModel();
	for( int i = 0; i < m->rowCount(); ++i )
	{
		r.writeStartElement( "DataFileDigest" );
		r.writeAttribute( XML_SCHEMA_INSTANCE, "type", QString( "m:" ).append( "DataFileDigest" ) );
		r.writeParameter( "Id", m->index( i, DocumentModel::Id ).data().toString() );
		r.writeParameter( "DigestType", "sha1" );
		r.writeParameter( "DigestValue", doc->getFileDigest( i ).toBase64() );
		r.writeEndElement();
	}
	r.writeEndElement();

	r.writeParameter( "Format", doc->documentType() == DigiDoc::BDocType ? "BDOC" : "DIGIDOC-XML" );
	r.writeParameter( "Version", doc->documentType() == DigiDoc::BDocType ? "1.0" : "1.3" );
	r.writeParameter( "SignatureID", doc->newSignatureID() );
	r.writeParameter( "MessagingMode", "asynchClientServer" );
	r.writeParameter( "AsyncConfiguration", 0 );
	r.writeEndDocument();

	request.setUrl( Settings().value( doc->documentType() == DigiDoc::BDocType ?
		"Client/bdocurl" : "Client/ddocurl", "https://digidocservice.sk.ee").toUrl() );
	statusTimer->start();
	manager->post( request, r.document() );
}

QByteArray MobileDialog::signature() const { return m_signature; }

void MobileDialog::sslErrors( QNetworkReply *reply, const QList<QSslError> &err )
{
	QSslCertificate digidocservice(
		"-----BEGIN CERTIFICATE-----\n"
		"MIIEjjCCA3agAwIBAgICJMQwDQYJKoZIhvcNAQEFBQAwbTELMAkGA1UEBhMCRUUx\n"
		"IjAgBgNVBAoTGUFTIFNlcnRpZml0c2VlcmltaXNrZXNrdXMxITAfBgNVBAsTGFNl\n"
		"cnRpZml0c2VlcmltaXN0ZWVudXNlZDEXMBUGA1UEAxMOS0xBU1MzLVNLIDIwMTAw\n"
		"HhcNMTIwNDEwMDgxNDMzWhcNMTYwODI2MDgwNzAwWjCBszEZMBcGCSqGSIb3DQEJ\n"
		"ARYKaW5mb0Bzay5lZTELMAkGA1UEBhMCRUUxETAPBgNVBAgMCEhhcmp1bWFhMRAw\n"
		"DgYDVQQHDAdUYWxsaW5uMSIwIAYDVQQKDBlBUyBTZXJ0aWZpdHNlZXJpbWlza2Vz\n"
		"a3VzMSEwHwYDVQQLDBhTZXJ0aWZpdHNlZXJpbWlzdGVlbnVzZWQxHTAbBgNVBAMM\n"
		"FGRpZ2lkb2NzZXJ2aWNlLnNrLmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
		"CgKCAQEAuFVuWiwzsSpcvXjcIUCE4twbHza1+nw9mA1WPWsVdMv42W+CuG+pIZYV\n"
		"f2+U6c0rdSZSTfJVdH8t9N/b6xKiN1eoN9wdNcNxfCP6NfKrtBGp+5wytkliEQ8r\n"
		"MG4bU+6kVHnFOxWChf1XntsFHCGgy03ooKaAyPNtKkJQGS8K2wlR22ODz8oJ8kwL\n"
		"kS+lUhLZ/KfdIgG/kMOt7hz1D0eEcyVVCD/HRuaCgDufdolkpdHJXKyGsTkdwm98\n"
		"Z61g7o+/ttONTbYbVCKK1NVe2SVkgoVphHuqm8jj3fsIpHGcMiF8+HRNYoB6Qz2A\n"
		"vIT+Qeoz/ISThA8RImfM56WOnhTjTQIDAQABo4HwMIHtMAkGA1UdEwQCMAAwPAYD\n"
		"VR0gBDUwMzAxBgsrBgEEAc4fBwECAjAiMCAGCCsGAQUFBwIBFhRodHRwOi8vd3d3\n"
		"LnNrLmVlL2NwczAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\n"
		"HwYDVR0jBBgwFoAUXXUUEYz0pY5Cj3uyQESj7tZ6O3IwPQYDVR0fBDYwNDAyoDCg\n"
		"LoYsaHR0cDovL3d3dy5zay5lZS9jcmxzL2tsYXNzMy9rbGFzczMtMjAxMC5jcmww\n"
		"HQYDVR0OBBYEFKonb+tVMFpSS/TCbJKeenhureWOMA0GCSqGSIb3DQEBBQUAA4IB\n"
		"AQCZfJV+zcpto8o6evT0ZEX9TGHhEejOpLRzhjE6UbRSmQbfNBNSkAPbqluuboHE\n"
		"iVZeejaj+JEXiDvsSufqI0pTjyNTSinS1XzJp3VLJRtQ+xf1ymJ6uxffNr1U3H1u\n"
		"sOF3Rar1iXfLEr9Vb86wPawdBRiIu3rqPuZknXS4/FZpFGEaV6Mc/L39ljQCbDT3\n"
		"+kZUTLEyhpGVLolm0r0fKCPC+blMB9VB5VTJ1o8Bv81Jc6S4O4gqDZLbDSX/yGAc\n"
		"eWpzL0m51PLo4Abt5ONN098YFKAHW11fypUAh1AH2sPtdufdDdrLcRez3kSlP35i\n"
		"7efI0hqlI4ilkb1ZUnIktJUd\n"
		"-----END CERTIFICATE-----\n" );
	QStringList msg;
	Q_FOREACH( const QSslError &e, err )
	{
		qWarning() << "SSL Error:" << e.error() << e.certificate().subjectInfo( "CN" );
		if( e.certificate() == digidocservice &&
			(e.error() == QSslError::UnableToGetLocalIssuerCertificate ||
			 e.error() == QSslError::UnableToVerifyFirstCertificate) )
		{
			reply->ignoreSslErrors( err );
			continue;
		}
		msg << e.errorString();
	}
	if( !msg.empty() )
		labelError->setText( QString("%1<br/>%2").arg( tr("SSL handshake failed") ).arg( msg.join( "<br />" ) ) );
}
