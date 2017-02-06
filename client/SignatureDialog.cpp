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

#include "SignatureDialog.h"

#include "ui_SignatureDialog.h"
#include "Application.h"

#include <common/CertificateWidget.h>
#include <common/Common.h>
#include <common/DateTime.h>
#include <common/SslCertificate.h>

#include <digidocpp/DataFile.h>

#include <QtCore/QTextStream>
#include <QtCore/QUrl>
#include <QtGui/QDesktopServices>
#include <QtGui/QTextDocument>
#include <QtNetwork/QSslKey>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>

SignatureWidget::SignatureWidget( const DigiDocSignature &signature, unsigned int signnum, QWidget *parent )
:	QLabel( parent )
,	num( signnum )
,	s( signature )
{
	setObjectName( QString("signatureWidget%1").arg(signnum) );
	setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Preferred );
	setWordWrap( true );
	setTextInteractionFlags( Qt::LinksAccessibleByKeyboard|Qt::LinksAccessibleByMouse );
	connect( this, SIGNAL(linkActivated(QString)), SLOT(link(QString)) );

	const SslCertificate cert = s.cert();
	QString accessibility, content, tooltip;
	QTextStream sa( &accessibility );
	QTextStream sc( &content );
	QTextStream st( &tooltip );

	if( cert.type() & SslCertificate::TempelType )
		sc << "<img src=\":/images/ico_stamp_blue_16.png\">";
	else
		sc << "<img src=\":/images/ico_person_blue_16.png\">";
	sc << "<b>" << cert.toString(cert.showCN() ? "CN" : "GN SN").toHtmlEscaped() << "</b>";

	if( !s.location().isEmpty() )
	{
		sa << " " << tr("Location") << " " << s.location();
		sc << "<br />" << s.location().toHtmlEscaped();
		st << s.location().toHtmlEscaped() << "<br />";
	}
	if( !s.role().isEmpty() )
	{
		sa << " " << tr("Role") << " " << s.role();
		sc << "<br />" << s.role().toHtmlEscaped();
		st << s.role().toHtmlEscaped() << "<br />";
	}
	DateTime date( s.dateTime().toLocalTime() );
	if( !date.isNull() )
	{
		sa << " " << tr("Signed on") << " "
			<< date.formatDate( "dd. MMMM yyyy" ) << " "
			<< tr("time") << " "
			<< date.toString( "hh:mm" );
		sc << "<br />" << tr("Signed on") << " "
			<< date.formatDate( "dd. MMMM yyyy" ) << " "
			<< tr("time") << " "
			<< date.toString( "hh:mm" );
		st << tr("Signed on") << " "
			<< date.formatDate( "dd. MMMM yyyy" ) << " "
			<< tr("time") << " "
			<< date.toString( "hh:mm" );
	}
	setToolTip( tooltip );

	sa << " " << tr("Signature is") << " ";
	sc << "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>";
	sc << "<td>" << tr("Signature is") << " ";
	switch( s.validate() )
	{
	case DigiDocSignature::Valid:
		sa << tr("valid");
		sc << "<font color=\"green\">" << tr("valid");
		break;
	case DigiDocSignature::Warning:
		sa << tr("valid") << " (" << tr("Warnings") << ")";
		sc << "<font color=\"green\">" << tr("valid") << "</font> <font>(" << tr("Warnings") << ")";
		break;
	case DigiDocSignature::Test:
		sa << tr("valid") << " (" << tr("Test signature") << ")";
		sc << "<font color=\"green\">" << tr("valid") << "</font> <font>(" << tr("Test signature") << ")";
		break;
	case DigiDocSignature::Invalid:
		sa << tr("not valid");
		sc << "<font color=\"red\">" << tr("not valid");
		break;
	case DigiDocSignature::Unknown:
		sa << tr("unknown");
		sc << "<font color=\"red\">" << tr("unknown");
		break;
	}
	sc << "</font>";
	sc << "</td><td align=\"right\">";
	sc << "<a href=\"details\" style=\"color: #509B00\" title=\"" << tr("Show details") << "\">" << tr("Show details") << "</a>";
	sc << "</td></tr><tr><td></td>";
	sc << "<td align=\"right\">";
	if( s.parent()->isSupported() )
		sc << "<a href=\"remove\" style=\"color: #509B00\" title=\"" << tr("Remove") << "\">" << tr("Remove") << "</a>";
	sc << "</td></tr></table>";

	setText( content );
	setAccessibleName( tr("Signature") + " " + cert.toString( cert.showCN() ? "CN" : "GN SN" ) );
	setAccessibleDescription( accessibility );
}

void SignatureWidget::link( const QString &url )
{
	if( url == "details" )
		(new SignatureDialog( s, qApp->activeWindow() ))->open();
	else if( url == "remove" )
	{
		SslCertificate c = s.cert();
		QString msg = tr("Remove signature %1")
			.arg( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) );
		QMessageBox::StandardButton b = QMessageBox::warning( qApp->activeWindow(), msg, msg,
			QMessageBox::Ok|QMessageBox::Cancel, QMessageBox::Cancel );
		if( b == QMessageBox::Ok )
			Q_EMIT removeSignature( num );
	}
}

void SignatureWidget::mouseDoubleClickEvent( QMouseEvent *e )
{
	if( e->button() == Qt::LeftButton )
		link( "details" );
}



class SignatureDialogPrivate: public Ui::SignatureDialog {};

SignatureDialog::SignatureDialog( const DigiDocSignature &signature, QWidget *parent )
:	QDialog( parent )
,	s( signature )
,	d( new SignatureDialogPrivate )
{
	d->setupUi( this );
	d->error->hide();
	setAttribute( Qt::WA_DeleteOnClose );

	SslCertificate c = signature.cert();
	QString status;
	switch( s.validate() )
	{
	case DigiDocSignature::Valid:
		status = tr("Signature is valid");
		break;
	case DigiDocSignature::Warning:
		status = QString("%1 (%2)").arg( tr("Signature is valid"), tr("Warnings") );
		if( !s.lastError().isEmpty() )
			d->error->setPlainText( s.lastError() );
		if( s.warning() & DigiDocSignature::WrongNameSpace )
		{
			d->info->setText( tr(
				"This Digidoc document has not been created according to specification, "
				"but the digital signature is legally valid. Please inform the document creator "
				"of this issue. <a href='http://www.id.ee/?id=36511'>Additional information</a>.") );
		}
		if( s.warning() & DigiDocSignature::DigestWeak )
		{
			d->info->setText( tr(
				"The current BDOC container uses weaker encryption method than officialy accepted in Estonia.") );
		}
		break;
	case DigiDocSignature::Test:
		status = QString("%1 (%2)").arg( tr("Signature is valid"), tr("Test signature") );
		if( !s.lastError().isEmpty() )
			d->error->setPlainText( s.lastError() );
		d->info->setText( tr(
			"Test signature is signed with test certificates that are similar to the "
			"certificates of real tokens, but digital signatures with legal force cannot "
			"be given with them as there is no actual owner of the card. "
			"<a href='http://www.id.ee/index.php?id=30494'>Additional information</a>.") );
		break;
	case DigiDocSignature::Invalid:
		status = tr("Signature is not valid");
		d->error->setPlainText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		d->info->setText( tr(
			"This is an invalid signature or malformed digitally signed file. The signature is not valid.") );
		break;
	case DigiDocSignature::Unknown:
		status = tr("Signature status unknown");
		d->error->setPlainText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		d->info->setText( tr(
			"Signature status is displayed \"unknown\" if you don't have all validity confirmation "
			"service certificates and/or certificate authority certificates installed into your computer "
			"(<a href='http://id.ee/?lang=en&id=34317'>additional information</a>) or digital signature "
			"does not meet all the requirements and signature is not equivalent to a handwritten signature.") );
		break;
	}
	if( d->error->toPlainText().isEmpty() && d->info->text().isEmpty() )
		d->tabWidget->removeTab( 0 );
	/*else
		d->buttonBox->addButton( QDialogButtonBox::Help );*/
	d->title->setText( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + "\n" + status );
	setWindowTitle( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + " - " + status );

	const QStringList l = s.locations();
	d->signerCity->setText( l.value( 0 ) );
	d->signerState->setText( l.value( 1 ) );
	d->signerZip->setText( l.value( 2 ) );
	d->signerCountry->setText( l.value( 3 ) );

	for( const QString &role: s.roles() )
	{
		QLineEdit *line = new QLineEdit( role, d->signerRoleGroup );
		line->setReadOnly( true );
		d->signerRoleGroupLayout->addRow( line );
	}

	// Certificate info
	QTreeWidget *t = d->signatureView;
	t->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

	addItem( t, tr("Signer's Certificate issuer"), c.issuerInfo( QSslCertificate::CommonName ) );
	addItem( t, tr("Signer's Certificate"), c );
	addItem( t, tr("Signature method"), QUrl( s.signatureMethod() ) );
	addItem( t, tr("Container format"), s.parent()->mediaType() );
	if( !s.profile().isEmpty() )
		addItem( t, tr("Signature format"), s.profile() );
	if( !s.policy().isEmpty() )
	{
		#define toVer(X) (X)->toUInt() - 1
		QStringList ver = s.policy().split( "." );
		if( ver.size() >= 3 )
			addItem( t, tr("Signature policy"), QString("%1.%2.%3").arg( toVer(ver.end()-3) ).arg( toVer(ver.end()-2) ).arg( toVer(ver.end()-1) ) );
		else
			addItem( t, tr("Signature policy"), s.policy() );
	}
	addItem( t, tr("Signed file count"), QString::number( s.parent()->documentModel()->rowCount() ) );
	if( !s.spuri().isEmpty() )
		addItem( t, "SPUri", QUrl( s.spuri() ) );

	if(!s.tsaTime().isNull())
	{
		SslCertificate tsa = s.tsaCert();
		addItem( t, tr("Archive Timestamp"), DateTime( s.tsaTime().toLocalTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ));
		addItem( t, tr("Archive Timestamp") + " (UTC)", DateTime( s.tsaTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( t, tr("Archive TS Certificate issuer"), tsa.issuerInfo(QSslCertificate::CommonName) );
		addItem( t, tr("Archive TS Certificate"), tsa );
	}
	if(!s.tsTime().isNull())
	{
		SslCertificate ts = s.tsCert();
		addItem( t, tr("Signature Timestamp"), DateTime( s.tsTime().toLocalTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ));
		addItem( t, tr("Signature Timestamp") + " (UTC)", DateTime( s.tsTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( t, tr("TS Certificate issuer"), ts.issuerInfo(QSslCertificate::CommonName) );
		addItem( t, tr("TS Certificate"), ts );
	}
	if(!s.ocspTime().isNull())
	{
		SslCertificate ocsp = s.ocspCert();
		addItem( t, tr("OCSP Certificate issuer"), ocsp.issuerInfo(QSslCertificate::CommonName) );
		addItem( t, tr("OCSP Certificate"), ocsp );
		addItem( t, tr("Hash value of signature"), SslCertificate::toHex( s.ocspNonce() ) );
		addItem( t, tr("OCSP time"), DateTime( s.ocspTime().toLocalTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( t, tr("OCSP time") + " (UTC)", DateTime( s.ocspTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
	}
	addItem( t, tr("Signer's computer time (UTC)"), DateTime( s.signTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
}

SignatureDialog::~SignatureDialog() { delete d; }

void SignatureDialog::addItem( QTreeWidget *view, const QString &variable, const QString &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, variable );
	i->setText( 1, value );
	view->addTopLevelItem( i );
}

void SignatureDialog::addItem( QTreeWidget *view, const QString &variable, const QSslCertificate &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, variable );
	QLabel *b = new QLabel( "<a href='cert'>" + SslCertificate(value).subjectInfo( QSslCertificate::CommonName ) + "</a>", view );
	b->setStyleSheet("margin-left: 2px");
	connect( b, &QLabel::linkActivated, [=](){ CertificateDialog( value, this ).exec(); });
	view->setItemWidget( i, 1, b );
	view->addTopLevelItem( i );
}

void SignatureDialog::addItem( QTreeWidget *view, const QString &variable, const QUrl &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, variable );
	QLabel *b = new QLabel( "<a href='url'>" + value.toString() + "</a>", view );
	b->setStyleSheet("margin-left: 2px");
	connect( b, &QLabel::linkActivated, [=](){ QDesktopServices::openUrl( value ); });
	view->setItemWidget( i, 1, b );
	view->addTopLevelItem( i );
}

void SignatureDialog::buttonClicked( QAbstractButton *button )
{
	if( button == d->buttonBox->button( QDialogButtonBox::Help ) )
		Common::showHelp( s.lastError(), s.lastErrorCode() );
	else if( button == d->buttonBox->button( QDialogButtonBox::Close ) )
		close();
}

void SignatureDialog::on_more_linkActivated( const QString & )
{
	d->error->setVisible( !d->error->isVisible() );
}
