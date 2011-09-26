/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2011 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2011 Raul Metsma <raul@innovaatik.ee>
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

#include "Application.h"
#include "DigiDoc.h"

#include <common/Settings.h>
#include <common/SOAPDocument.h>
#include <common/SslCertificate.h>

#include <digidocpp/Document.h>
#include <digidocpp/Exception.h>
#include <digidocpp/crypto/Digest.h>

#include <QDir>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslKey>
#include <QSslConfiguration>
#include <QTimeLine>
#include <QXmlStreamReader>

using namespace digidoc;

MobileDialog::MobileDialog( DigiDoc *doc, QWidget *parent )
:	QDialog( parent )
,	m_doc( doc )
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

	statusTimer = new QTimeLine( signProgressBar->maximum() * 1000, this );
	statusTimer->setCurveShape( QTimeLine::LinearCurve );
	statusTimer->setFrameRange( signProgressBar->minimum(), signProgressBar->maximum() );
	connect( statusTimer, SIGNAL(frameChanged(int)), SLOT(sendStatusRequest(int)) );
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

	if ( m_doc->documentType() == WDoc::BDocType )
		request.setUrl( QUrl( Settings().value("Client/bdocurl", "https://digidocservice.sk.ee").toString() ) );
	else
		request.setUrl( QUrl( Settings().value("Client/ddocurl", "https://digidocservice.sk.ee").toString() ) );

	QFile f( Application::confValue( Application::PKCS12Cert ).toString() );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	PKCS12Certificate pkcs12Cert( &f, Application::confValue( Application::PKCS12Pass ).toString().toUtf8() );
	if( pkcs12Cert.isNull() )
		return;

	QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
	ssl.setPrivateKey( pkcs12Cert.key() );
	ssl.setLocalCertificate( pkcs12Cert.certificate() );
#ifdef Q_OS_LINUX
	ssl.setCaCertificates( ssl.caCertificates() + QSslCertificate::fromPath(
		QString( qApp->confValue( Application::CertStorePath ).toString() ).append( "/*" ), QSsl::Pem, QRegExp::Wildcard ) );
#endif
	request.setSslConfiguration( ssl );
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
			code->setText( tr("Make sure control code matches with one in phone screen\n"
				"and enter Mobile-ID PIN.\nControl code: %1").arg( challenge ) );
		return;
	}

	if( statusTimer->state() == QTimeLine::NotRunning )
		return;
	labelError->setText( mobileResults.value( status ) );
	if( status == "REQUEST_OK" || status == "OUTSTANDING_TRANSACTION" )
		return;
	statusTimer->stop();
	if( status == "SIGNATURE" )
		close();
}

void MobileDialog::sendStatusRequest( int frame )
{
	signProgressBar->setValue( frame );
	if( frame % 5 != 0 )
		return;
	SOAPDocument doc( "GetMobileCreateSignatureStatus", DIGIDOCSERVICE );
	doc.writeParameter( "Sesscode", sessionCode.toInt() );
	doc.writeParameter( "WaitSignature", false );
	doc.finalize();
	manager->post( request, doc.document() );
}

void MobileDialog::setSignatureInfo( const QString &city, const QString &state, const QString &zip,
	const QString &country, const QString &role, const QString &role2 )
{
	roles = QStringList() << role << role2;
	roles.removeAll( "" );
	location = QStringList() << city << state << zip << country;
}

void MobileDialog::sign( const QString &ssid, const QString &cell )
{
	labelError->setText( mobileResults.value( "START" ) );

	QHash<QString,QString> lang;
	lang["et"] = "EST";
	lang["en"] = "ENG";
	lang["ru"] = "RUS";

	SOAPDocument r( "MobileCreateSignature", DIGIDOCSERVICE );
	r.writeParameter( "IDCode", ssid );
	r.writeParameter( "PhoneNo", cell );
	r.writeParameter( "Language", lang.value( Settings::language(), "EST" ) );
	r.writeParameter( "ServiceName", "DigiDoc3" );
	r.writeParameter( "MessageToDisplay", tr("Sign") );
	r.writeParameter( "City", location.value(0) );
	r.writeParameter( "StateOrProvince", location.value(1) );
	r.writeParameter( "PostalCode", location.value(2) );
	r.writeParameter( "CountryName", location.value(3) );
	r.writeParameter( "Role", roles.join(" / ") );
	r.writeParameter( "SigningProfile", "" );

	r.writeStartElement( "DataFiles" );
	r.writeAttribute( XML_SCHEMA_INSTANCE, "type", "m:DataFileDigestList" );

	DocumentModel *m = m_doc->documentModel();
	for( int i = 0; i < m->rowCount(); ++i )
	{
		QByteArray digest;
		QString name = "sha1";
		if( m_doc->documentType() == WDoc::BDocType )
		{
			try
			{
				std::auto_ptr<Digest> calc(new Digest( URI_SHA1 ));
				Document file = m->document( m->index( i, 0 ) );
				std::vector<unsigned char> d = file.calcDigest( calc.get() );
				digest = QByteArray( (char*)&d[0], d.size() );
				name = QString::fromUtf8( calc->getName().c_str() );
			}
			catch( const IOException &e )
			{
				labelError->setText( QString::fromUtf8( e.getMsg().c_str() ) );
				return;
			}
		}
		else
			digest = m_doc->getFileDigest( i ).left( 20 );

		r.writeStartElement( "DataFileDigest" );
		r.writeAttribute( XML_SCHEMA_INSTANCE, "type", QString( "m:" ).append( "DataFileDigest" ) );
		r.writeParameter( "Id", m_doc->documentType() == WDoc::BDocType ?
			QString( "/%1" ).arg( m->index( i, 0 ).data().toString() ) : QString( "D%1" ).arg( i ) );
		r.writeParameter( "DigestType", name );
		r.writeParameter( "DigestValue", digest.toBase64() );
		r.writeEndElement();
	}
	r.writeEndElement();

	r.writeParameter( "Format", m_doc->documentType() == WDoc::BDocType ? "BDOC" : "DIGIDOC-XML" );
	r.writeParameter( "Version", m_doc->documentType() == WDoc::BDocType ? "1.0" : "1.3" );
	r.writeParameter( "SignatureID", QString( "S%1" ).arg( m_doc->signatures().size() ) );
	r.writeParameter( "MessagingMode", "asynchClientServer" );
	r.writeParameter( "AsyncConfiguration", 0 );
	r.finalize();

	manager->post( request, r.document() );
	statusTimer->start();
}

QByteArray MobileDialog::signature() const { return m_signature; }

void MobileDialog::sslErrors( QNetworkReply *reply, const QList<QSslError> &err )
{
	QStringList msg;
	Q_FOREACH( const QSslError &e, err )
	{
		QString s = e.errorString();
		if( !e.certificate().isNull() )
			s.append( QString( " - \"%1\"").arg( e.certificate().subjectInfo( "CN" ) ) );
		msg << s;
	}
	reply->ignoreSslErrors();
	return;
	labelError->setText( QString("%1<br/>%2").arg( tr("SSL handshake failed") ).arg( msg.join( "<br />" ) ) );
}
