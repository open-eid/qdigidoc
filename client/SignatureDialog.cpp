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

#include "SignatureDialog.h"

#include "ui_SignatureDialog.h"

#include <common/CertificateWidget.h>
#include <common/Common.h>
#include <common/DateTime.h>
#include <common/SslCertificate.h>

#include <digidocpp/DataFile.h>

#include <QtCore/QTextStream>
#include <QtCore/QUrl>
#if QT_VERSION >= 0x050000
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#else
#include <QtGui/QMessageBox>
#include <QtGui/QPushButton>
#endif
#include <QtGui/QDesktopServices>
#include <QtGui/QTextDocument>
#include <QtNetwork/QSslKey>

SignatureWidget::SignatureWidget( const DigiDocSignature &signature, unsigned int signnum, QWidget *parent )
:	QLabel( parent )
,	num( signnum )
,	s( signature )
{
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
	sc << "<b>" << Qt::escape( cert.toString( cert.showCN() ? "CN" : "GN SN" ) ) << "</b>";

	if( !s.location().isEmpty() )
	{
		sa << " " << tr("Location") << " " << s.location();
		sc << "<br />" << Qt::escape( s.location() );
		st << Qt::escape( s.location() ) << "<br />";
	}
	if( !s.role().isEmpty() )
	{
		sa << " " << tr("Role") << " " << s.role();
		sc << "<br />" << Qt::escape( s.role() );
		st << Qt::escape( s.role() ) << "<br />";
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
	case DigiDocSignature::Warning: // Fall to Valid
	case DigiDocSignature::Valid:
		sa << tr("valid");
		sc << "<font color=\"green\">" << tr("valid");
		break;
	case DigiDocSignature::Test:
		sa << " " << tr("Test signature");
		sc << " (" << tr("Test signature") << ")";
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
	if( s.parent()->isSupported() && !(s.warning() & DigiDocSignature::WrongNameSpace) )
		sc << "<a href=\"remove\" style=\"color: #509B00\" title=\"" << tr("Remove") << "\">" << tr("Remove") << "</a>";
	sc << "</td></tr></table>";

	setText( content );
	setAccessibleName( tr("Signature") + " " + cert.toString( cert.showCN() ? "CN" : "GN SN" ) );
	setAccessibleDescription( accessibility );
}

void SignatureWidget::link( const QString &url )
{
	if( url == "details" )
		(new SignatureDialog( s, qApp->activeWindow() ))->show();
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



class SignatureDialogPrivate: public Ui::SignatureDialog
{
public:
	SignatureDialogPrivate(): signCert(0), ocspCert(0) {}

	QAbstractButton *signCert, *ocspCert;
};

SignatureDialog::SignatureDialog( const DigiDocSignature &signature, QWidget *parent )
:	QWidget( parent )
,	s( signature )
,	d( new SignatureDialogPrivate )
{
	d->setupUi( this );
	setAttribute( Qt::WA_DeleteOnClose );
	setWindowFlags( Qt::Sheet );

	const SslCertificate c = s.cert();
	if( !s.cert().isNull() )
		d->signCert = d->buttonBox->addButton( tr("Show signer's certificate"), QDialogButtonBox::ActionRole );
	if( !s.ocspCert().isNull() )
		d->ocspCert = d->buttonBox->addButton( tr("Show OCSP certificate"), QDialogButtonBox::ActionRole );

	QString status;
	switch( s.validate() )
	{
	case DigiDocSignature::Valid:
		status = tr("Signature is valid");
		break;
	case DigiDocSignature::Warning:
		status = tr("Signature has warnings");
		if( !s.lastError().isEmpty() )
			d->error->setPlainText( s.lastError() );
		break;
	case DigiDocSignature::Test:
		status = tr("Test signature");
		if( !s.lastError().isEmpty() )
			d->error->setPlainText( s.lastError() );
		break;
	case DigiDocSignature::Invalid:
		status = tr("Signature is not valid");
		d->error->setPlainText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		break;
	case DigiDocSignature::Unknown:
		status = tr("Signature status unknown");
		d->error->setPlainText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		break;
	}
	if( d->error->toPlainText().isEmpty() )
		d->tabWidget->removeTab( 0 );
	else
		d->buttonBox->addButton( QDialogButtonBox::Help );
	d->title->setText( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + "\n" + status );
	setWindowTitle( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + " - " + status );

	const QStringList l = s.locations();
	d->signerCity->setText( l.value( 0 ) );
	d->signerState->setText( l.value( 1 ) );
	d->signerZip->setText( l.value( 2 ) );
	d->signerCountry->setText( l.value( 3 ) );

	Q_FOREACH( const QString &role, s.roles() )
	{
		QLineEdit *line = new QLineEdit( role, d->signerRoleGroup );
		line->setReadOnly( true );
		d->signerRoleGroupLayout->addRow( line );
	}

	// Certificate info
	QTreeWidget *t = d->signatureView;
	t->header()->setResizeMode( 0, QHeaderView::ResizeToContents );
	addItem( t, tr("Signer's computer time"), DateTime( s.signTime().toLocalTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
	addItem( t, tr("Signer's computer time (UTC)"), DateTime( s.signTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
	addItem( t, tr("Signature method"), s.signatureMethod() );
	addItem( t, tr("Container format"), s.parent()->mediaType() );
	if( s.type() != DigiDocSignature::DDocType )
		addItem( t, tr("Signature format"), s.profile() );
	if( !s.policy().isEmpty() )
		addItem( t, tr("Signature policy"), s.policy() );
	addItem( t, tr("Signed file count"), QString::number( s.parent()->documentModel()->rowCount() ) );
	//addItem( t, tr("Signer Certificate issuer"), c.issuerInfo( QSslCertificate::CommonName ) );
	if( !s.spuri().isEmpty() )
		addItem( t, "SPUri", s.spuri() );

	// OCSP info
	if( s.type() == DigiDocSignature::DDocType ||
		s.type() == DigiDocSignature::TMType )
	{
		SslCertificate ocsp = s.ocspCert();
		addItem( t, tr("OCSP Certificate issuer"), ocsp.issuerInfo( QSslCertificate::CommonName ) );
		addItem( t, tr("OCSP time"), DateTime( s.ocspTime().toLocalTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( t, tr("OCSP time (UTC)"), DateTime( s.ocspTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( t, tr("Hash value of signature"), SslCertificate::toHex( s.ocspNonce() ) );
	}
}

SignatureDialog::~SignatureDialog() { delete d; }

void SignatureDialog::addItem( QTreeWidget *view, const QString &variable, const QString &value )
{
	QTreeWidgetItem *i = new QTreeWidgetItem( view );
	i->setText( 0, variable );
	i->setText( 1, value );
	view->addTopLevelItem( i );
}

void SignatureDialog::buttonClicked( QAbstractButton *button )
{
	if( button == d->buttonBox->button( QDialogButtonBox::Help ) )
		Common::showHelp( s.lastError(), s.lastErrorCode() );
	else if( button == d->buttonBox->button( QDialogButtonBox::Close ) )
		close();
	else if( button == d->signCert )
		CertificateDialog( s.cert(), this ).exec();
	else if( button == d->ocspCert )
		CertificateDialog( s.ocspCert(), this ).exec();
}

void SignatureDialog::on_signatureView_doubleClicked( const QModelIndex &index )
{
	if( index.row() == 8 && index.column() == 1 )
		QDesktopServices::openUrl( index.data().toUrl() );
}
