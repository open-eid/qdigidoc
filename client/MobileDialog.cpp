/*
 * QDigiDocClient
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

#include "MobileDialog.h"
#include "DigiDoc.h"

#include <common/Settings.h>
#include <common/SslCertificate.h>

#include <digidocpp/Document.h>
#include <digidocpp/Exception.h>
#include <digidocpp/crypto/Digest.h>
#include <digidocpp/WDoc.h>

#include <QDir>
#include <QDomElement>
#include <QNetworkAccessManager>
#include <QNetworkProxy>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QSslKey>
#include <QSslConfiguration>
#include <QTemporaryFile>
#include <QTimeLine>

MobileDialog::MobileDialog( DigiDoc *doc, QWidget *parent )
:	QDialog( parent )
,	m_doc( doc )
,	sessionCode( 0 )
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
	mobileResults["OCSP_UNAUTHORIZED"] = tr("Not allowed to use OCSP service!\nPlease check your server access sertificate.");
	mobileResults["HOSTNOTFOUND"] = tr("Connecting to SK server failed!\nPlease check your internet connection.");
	mobileResults["User is not a Mobile-ID client"] = tr("User is not a Mobile-ID client");
	mobileResults["ID and phone number do not match"] = tr("ID and phone number do not match");
	mobileResults["Certificate status unknown"] = tr("Certificate status unknown");

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

	if( !DigiDoc::getConfValue( DigiDoc::ProxyHost ).isEmpty() )
	{
		manager->setProxy( QNetworkProxy(
			QNetworkProxy::HttpProxy,
			DigiDoc::getConfValue( DigiDoc::ProxyHost ),
			DigiDoc::getConfValue( DigiDoc::ProxyPort ).toUInt(),
			DigiDoc::getConfValue( DigiDoc::ProxyUser ),
			DigiDoc::getConfValue( DigiDoc::ProxyPass ) ) );
	}

	if ( m_doc->documentType() == digidoc::WDoc::BDocType )
		request.setUrl( QUrl( Settings().value("Client/bdocurl", "https://www.sk.ee:8097").toString() ) );
	else
		request.setUrl( QUrl( Settings().value("Client/ddocurl", "https://digidocservice.sk.ee").toString() ) );

	QString certFile = DigiDoc::getConfValue( DigiDoc::PKCS12Cert );
	if( certFile.isEmpty() || !QFile::exists( certFile ) )
		return;

	QFile f( certFile );
	if( !f.open( QIODevice::ReadOnly ) )
		return;

	PKCS12Certificate pkcs12Cert( &f, DigiDoc::getConfValue( DigiDoc::PKCS12Pass ).toLatin1() );
	if( pkcs12Cert.isNull() )
		return;

	QSslConfiguration ssl;
	ssl.setPrivateKey( pkcs12Cert.key() );
	ssl.setLocalCertificate( pkcs12Cert.certificate() );
	request.setSslConfiguration( ssl );
}

QString MobileDialog::elementText( const QDomElement &element, const QString &tag ) const
{ return element.elementsByTagName( tag ).item(0).toElement().text(); }

void MobileDialog::endProgress()
{ labelError->setText( mobileResults.value( "EXPIRED_TRANSACTION" ) ); }

QString MobileDialog::escapeChars( const QString &in ) const
{
	QString out;
	out.reserve( in.size() );
	for( QString::ConstIterator i = in.constBegin(); i != in.constEnd(); ++i )
	{
		if( *i == '\'' ) out += "&apos;";
		else if( *i == '\"' ) out += "&quot;";
		else if( *i == '<' ) out += "&lt;";
		else if( *i == '>' ) out += "&gt;";
		else if( *i == '&' ) out += "&amp;";
		else out += *i;
	}
	return out;
}

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
	default:
		labelError->setText( reply->errorString() );
		statusTimer->stop();
		reply->deleteLater();
		return;
	}

	QByteArray result = reply->readAll();
	reply->deleteLater();
	if( result.isEmpty() )
	{
		labelError->setText( tr("Empty HTTP result") );
		statusTimer->stop();
		return;
	}

	QDomDocument doc;
	if( !doc.setContent( QString::fromUtf8( result ) ) )
	{
		labelError->setText( tr("Failed to parse XML document") );
		statusTimer->stop();
		return;
	}

	QDomElement e = doc.documentElement();
	if( result.contains( "Fault" ) )
	{
		QString error = elementText( e, "message" );
		if( mobileResults.contains( error.toLatin1() ) )
			error = mobileResults.value( error.toLatin1() );
		labelError->setText( error );
		statusTimer->stop();
		return;
	}

	if( !sessionCode )
	{
		sessionCode = elementText( e, "Sesscode" ).toInt();
		if ( !sessionCode )
		{
			labelError->setText( mobileResults.value( elementText( e, "message" ).toLatin1() ) );
			statusTimer->stop();
		}
		else
			code->setText( tr("Control code: %1").arg( elementText( e, "ChallengeID" ) ) );
		return;
	}

	if( statusTimer->state() == QTimeLine::NotRunning )
		return;

	QString status = elementText( e, "Status" );
	labelError->setText( mobileResults.value( status.toLatin1() ) );

	if( status == "REQUEST_OK" || status == "OUTSTANDING_TRANSACTION" )
		return;

	statusTimer->stop();

	if( status != "SIGNATURE" )
		return;

	QTemporaryFile file( QString( "%1/XXXXXX.xml" ).arg( QDir::tempPath() ) );
	file.setAutoRemove( false );
	if( !file.open() )
		return;

	fName = file.fileName();
	file.write( "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\" ?>\n" );
	if ( m_doc->documentType() == digidoc::WDoc::DDocType )
		file.write( "<SignedDoc format=\"DIGIDOC-XML\" version=\"1.3\" xmlns=\"http://www.sk.ee/DigiDoc/v1.3.0#\">\n" );
	file.write( elementText( e, "Signature" ).toUtf8() );
	if ( m_doc->documentType() == digidoc::WDoc::DDocType )
		file.write( "</SignedDoc>" );
	file.close();
	close();
}

void MobileDialog::sendStatusRequest( int frame )
{
	signProgressBar->setValue( frame );
	if( frame % 5 != 0 )
		return;
	QString message = QString(
		"<Sesscode xsi:type=\"xsd:int\">%1</Sesscode>"
		"<WaitSignature xsi:type=\"xsd:boolean\">false</WaitSignature>" )
		.arg( sessionCode );
	manager->post( request, insertBody( "GetMobileCreateSignatureStatus", message ).toUtf8() );
}

void MobileDialog::setSignatureInfo( const QString &city, const QString &state, const QString &zip,
	const QString &country, const QString &role, const QString &role2 )
{
	QStringList roles = QStringList() << role << role2;
	roles.removeAll( "" );
	signature = QString(
		"<City xsi:type=\"xsd:String\">%1</City>"
		"<StateOrProvince xsi:type=\"xsd:String\">%2</StateOrProvince>"
		"<PostalCode xsi:type=\"xsd:String\">%3</PostalCode>"
		"<CountryName xsi:type=\"xsd:String\">%4</CountryName>"
		"<Role xsi:type=\"xsd:String\">%5</Role>")
		.arg( escapeChars( city ) )
		.arg( escapeChars( state ) )
		.arg( escapeChars( zip ) )
		.arg( escapeChars( country ) )
		.arg( escapeChars( roles.join(" / ") ) );
}

void MobileDialog::sign( const QString &ssid, const QString &cell )
{
	if ( !getFiles() )
		return;

	labelError->setText( mobileResults.value( "START" ) );

	QHash<QString,QString> lang;
	lang["et"] = "EST";
	lang["en"] = "ENG";
	lang["ru"] = "RUS";

	QString message = QString(
		"<IDCode xsi:type=\"xsd:String\">%1</IDCode>"
		"<PhoneNo xsi:type=\"xsd:String\">%2</PhoneNo>"
		"<Language xsi:type=\"xsd:String\">%3</Language>"
		"<ServiceName xsi:type=\"xsd:String\">DigiDoc3</ServiceName>"
		"<MessageToDisplay xsi:type=\"xsd:String\">%4</MessageToDisplay>"
		"%5"
		"<SigningProfile xsi:type=\"xsd:String\"></SigningProfile>"
		"%6"
		"<Format xsi:type=\"xsd:String\">%7</Format>"
		"<Version xsi:type=\"xsd:String\">%8</Version>"
		"<SignatureID xsi:type=\"xsd:String\">S%9</SignatureID>"
		"<MessagingMode xsi:type=\"xsd:String\">asynchClientServer</MessagingMode>"
		"<AsyncConfiguration xsi:type=\"xsd:int\">0</AsyncConfiguration>" )
		.arg( escapeChars( ssid ) )
		.arg( escapeChars( cell ) )
		.arg( lang.value( Settings().value("Main/Language", "et" ).toString(), "EST" ) )
		.arg( tr("Sign") )
		.arg( signature )
		.arg( files )
		.arg( m_doc->documentType() == digidoc::WDoc::BDocType ? "BDOC" : "DIGIDOC-XML" )
		.arg( m_doc->documentType() == digidoc::WDoc::BDocType ? "1.0" : "1.3" )
		.arg( m_doc->signatures().size() );
	manager->post( request, insertBody( "MobileCreateSignature", message ).toUtf8() );
	statusTimer->start();
}

void MobileDialog::sslErrors( QNetworkReply *reply, const QList<QSslError> & )
{ reply->ignoreSslErrors(); }

bool MobileDialog::getFiles()
{
	files = "<DataFiles xsi:type=\"m:DataFileDigestList\">";
	int i = 0;
	Q_FOREACH( digidoc::Document file, m_doc->documents() )
	{
		QByteArray digest;
		QString name = "sha1";
		if ( m_doc->documentType() == digidoc::WDoc::BDocType )
		{
			std::auto_ptr<digidoc::Digest> calc = digidoc::Digest::create();
			std::vector<unsigned char> d;
			try {
				 d = file.calcDigest( calc.get() );
			} catch( const digidoc::IOException &e ) {
				labelError->setText( QString::fromStdString( e.getMsg() ) );
				return false;
			}
			digest = QByteArray( (char*)&d[0], d.size() );
			name = QString::fromStdString( calc->getName() );
		} else
			digest = m_doc->getFileDigest( i ).left( 20 );

		QFileInfo f( QString::fromStdString( file.getPath() ) );
		files += QString(
			"<DataFileDigest xsi:type=\"m:DataFileDigest\">"
			"<Id xsi:type=\"xsd:String\">%1</Id>"
			"<DigestType xsi:type=\"xsd:String\">%2</DigestType>"
			"<DigestValue xsi:type=\"xsd:String\">%3</DigestValue>"
			"</DataFileDigest>" )
			.arg( m_doc->documentType() == digidoc::WDoc::BDocType ?
				"/" + f.fileName() : "D" + QString::number( i ) )
			.arg( escapeChars( name ) ).arg( digest.toBase64().constData() );
		i++;
	}
	files += "</DataFiles>";
	return true;
}

QString MobileDialog::insertBody( const QString &action, const QString &body ) const
{
	return QString(
		"<SOAP-ENV:Envelope"
		"	xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
		"	xmlns:SOAP-ENC=\"http://schemas.xmlsoap.org/soap/encoding/\""
		"	xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
		"	xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\">"
		"<SOAP-ENV:Body>"
		"<m:%1"
		"	xmlns:m=\"http://www.sk.ee/DigiDocService/DigiDocService_2_3.wsdl\""
		"	SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">%2</m:%1>"
		"</SOAP-ENV:Body>"
		"</SOAP-ENV:Envelope>" ).arg( action ).arg( body );
}
