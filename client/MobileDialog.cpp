/*
 * QDigiDocClient
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
#ifdef Q_OS_WIN
#include <QtWinExtras/QWinTaskbarButton>
#include <QtWinExtras/QWinTaskbarProgress>
#endif

using namespace digidoc;

MobileDialog::MobileDialog( QWidget *parent )
	: QDialog(parent)
	, taskbar(nullptr)
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
	mobileResults["Invalid PhoneNo"] = tr("Invalid phone number! Please include correct country code.");
	mobileResults["User is not a Mobile-ID client"] = tr("User is not a Mobile-ID client");
	mobileResults["ID and phone number do not match"] = tr("ID and phone number do not match");
	mobileResults["Certificate status unknown"] = tr("Your Mobile-ID service is not activated.");
	mobileResults["Certificate is revoked"] = tr("Mobile-ID user certificates are revoked or suspended.");

	setupUi( this );
	code->setBuddy( signProgressBar );

	statusTimer = new QTimeLine( signProgressBar->maximum() * 1000, this );
	statusTimer->setCurveShape( QTimeLine::LinearCurve );
	statusTimer->setFrameRange( signProgressBar->minimum(), signProgressBar->maximum() );
	connect( statusTimer, SIGNAL(frameChanged(int)), signProgressBar, SLOT(setValue(int)) );
	connect( statusTimer, SIGNAL(finished()), SLOT(endProgress()) );
#ifdef Q_OS_WIN
	taskbar = new QWinTaskbarButton(this);
	taskbar->setWindow(parent->windowHandle());
	taskbar->progress()->setRange(signProgressBar->minimum(), signProgressBar->maximum());
	connect(statusTimer, &QTimeLine::frameChanged, taskbar->progress(), &QWinTaskbarProgress::setValue);
#endif

	manager = new QNetworkAccessManager( this );
	connect( manager, SIGNAL(finished(QNetworkReply*)), SLOT(finished(QNetworkReply*)) );
	connect( manager, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)),
		SLOT(sslErrors(QNetworkReply*,QList<QSslError>)) );

	if( !Application::confValue( Application::PKCS12Disable ).toBool() )
	{
		QSslConfiguration ssl = QSslConfiguration::defaultConfiguration();
		ssl.setCaCertificates( ssl.caCertificates()
			<< QSslCertificate::fromPath( ":/certs/*.crt", QSsl::Pem, QRegExp::Wildcard ) );
		ssl.setPrivateKey( AccessCert::key() );
		ssl.setLocalCertificate( AccessCert::cert() );
		request.setSslConfiguration( ssl );
	}

	request.setHeader( QNetworkRequest::ContentTypeHeader, "text/xml" );
	request.setRawHeader( "User-Agent", QString( "%1/%2 (%3)")
		.arg( qApp->applicationName() ).arg( qApp->applicationVersion() ).arg( Common::applicationOs() ).toUtf8() );
}

void MobileDialog::endProgress()
{
	labelError->setText( mobileResults.value( "EXPIRED_TRANSACTION" ) );
	stop();
}

void MobileDialog::finished( QNetworkReply *reply )
{
	switch( reply->error() )
	{
	case QNetworkReply::NoError:
	case QNetworkReply::UnknownContentError:
#if QT_VERSION >= QT_VERSION_CHECK(5,3,0)
	case QNetworkReply::InternalServerError:
#endif
		break;
	case QNetworkReply::HostNotFoundError:
		labelError->setText( mobileResults.value( "HOSTNOTFOUND" ) );
		stop();
		reply->deleteLater();
		return;
	case QNetworkReply::SslHandshakeFailedError:
		stop();
		reply->deleteLater();
		return;
	default:
		labelError->setText( reply->errorString() );
		stop();
		reply->deleteLater();
		return;
	}

	QXmlStreamReader xml( reply );
	QString fault, message, status;
	while( xml.readNext() != QXmlStreamReader::Invalid )
	{
		if( !xml.isStartElement() )
			continue;
		if( xml.name() == "faultstring" )
			fault = xml.readElementText();
		else if( xml.name() == "message" )
			message = xml.readElementText();
		else if( xml.name() == "ChallengeID" )
		{
			code->setText( tr("Make sure control code matches with one in phone screen\n"
				"and enter Mobile-ID PIN2-code.\nControl code: %1").arg( xml.readElementText() ) );
			code->setAccessibleName( code->text() );
		}
		else if( xml.name() == "Sesscode" )
			sessionCode = xml.readElementText();
		else if( xml.name() == "Status" )
			status = xml.readElementText();
		else if( xml.name() == "Signature" )
			m_signature = xml.readElementText().toUtf8();
	}
	reply->deleteLater();

	if( !fault.isEmpty() )
	{
		labelError->setText( mobileResults.value( message, message ) );
		stop();
		return;
	}

	if( sessionCode.isEmpty() )
	{
		labelError->setText( mobileResults.value( message ) );
		stop();
		return;
	}

	if( statusTimer->state() == QTimeLine::NotRunning )
		return;

	labelError->setText( mobileResults.value( status ) );
	if( status == "OK" || status == "REQUEST_OK" || status == "OUTSTANDING_TRANSACTION" )
	{
		QTimer::singleShot(5*1000, this, SLOT(sendStatusRequest()));
		return;
	}
	stop();
	if( status == "SIGNATURE" )
		accept();
}

bool MobileDialog::isTest( const QString &ssid, const QString &cell )
{
	const static QStringList list = QStringList()
		<< "14212128020" "37200002"
		<< "14212128021" "37200003"
		<< "14212128022" "37200004"
		<< "14212128023" "37200005"
		<< "14212128024" "37200006"
		<< "14212128025" "37200007"
		<< "14212128026" "37200008"
		<< "14212128027" "37200009"
		<< "38002240211" "37200001"
		<< "14212128029" "37200001066";
	return list.contains( ssid + cell );
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
	r.writeParameter( "SigningProfile", doc->signatureFormat() );

	r.writeStartElement( "DataFiles" );
	r.writeAttribute( XML_SCHEMA_INSTANCE, "type", "m:DataFileDigestList" );
	DocumentModel *m = doc->documentModel();
	bool ddoc = doc->documentType() == DigiDoc::DDocType;
	for( int i = 0; i < m->rowCount(); ++i )
	{
		r.writeStartElement( "DataFileDigest" );
		r.writeAttribute( XML_SCHEMA_INSTANCE, "type", QString( "m:" ).append( "DataFileDigest" ) );
		r.writeParameter( "Id", m->index( i, DocumentModel::Id ).data().toString() );
		r.writeParameter( "DigestType", ddoc ? "sha1" : "sha256" );
		r.writeParameter( "DigestValue", doc->getFileDigest( i ).toBase64() );
		r.writeParameter( "MimeType", m->index( i, DocumentModel::Mime ).data().toString() );
		r.writeEndElement();
	}
	r.writeEndElement();

	r.writeParameter( "Format", ddoc ? "DIGIDOC-XML" : "BDOC" );
	r.writeParameter( "Version", ddoc ? "1.3" : "2.1" );
	r.writeParameter( "SignatureID", doc->newSignatureID() );
	r.writeParameter( "MessagingMode", "asynchClientServer" );
	r.writeParameter( "AsyncConfiguration", 0 );
	r.writeEndDocument();

	QString url = isTest( ssid, cell ) ?
		"https://tsp.demo.sk.ee" : "https://digidocservice.sk.ee";
	request.setUrl( Settings().value( ddoc ? "Client/ddocurl" : "Client/bdocurl", url ).toUrl() );
	statusTimer->start();
#ifdef Q_OS_WIN
	taskbar->progress()->show();
	taskbar->progress()->resume();
#endif
	manager->post( request, r.document() );
}

QByteArray MobileDialog::signature() const { return m_signature; }

void MobileDialog::sslErrors( QNetworkReply *, const QList<QSslError> &err )
{
	QStringList msg;
	for( const QSslError &e: err )
	{
		qWarning() << "SSL Error:" << e.error() << e.certificate().subjectInfo( "CN" );
		msg << e.errorString();
	}
	if( !msg.empty() )
	{
		msg.prepend( tr("SSL handshake failed. Check the proxy settings of your computer or software upgrades.") );
		labelError->setText( msg.join( "<br />" ) );
	}
}

void MobileDialog::stop()
{
	statusTimer->stop();
#ifdef Q_OS_WIN
	taskbar->progress()->stop();
	taskbar->progress()->hide();
#endif
}
