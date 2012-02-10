/*
 * QDigiDocClient
 *
 * Copyright (C) 2009-2012 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009-2012 Raul Metsma <raul@innovaatik.ee>
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

#include <digidocpp/Document.h>

#include <QDateTime>
#include <QDesktopServices>
#include <QMessageBox>
#include <QPushButton>
#include <QSslKey>
#include <QTextDocument>
#include <QTextStream>
#include <QUrl>

SignatureWidget::SignatureWidget( const DigiDocSignature &signature, unsigned int signnum, QWidget *parent )
:	QLabel( parent )
,	num( signnum )
,	s( signature )
{
	setSizePolicy( QSizePolicy::Ignored, QSizePolicy::Preferred );
	setWordWrap( true );
	const SslCertificate cert = s.cert();
	QString content;
	QTextStream st( &content );

	if( cert.isTempel() )
		st << "<img src=\":/images/ico_stamp_blue_16.png\">";
	else
		st << "<img src=\":/images/ico_person_blue_16.png\">";
	st << "<b>" << Qt::escape( cert.toString( cert.showCN() ? "CN" : "GN SN" ) ) << "</b>";

	QString tooltip;
	QTextStream t( &tooltip );
	QDateTime date = s.dateTime();
	if( !s.location().isEmpty() )
	{
		st << "<br />" << Qt::escape( s.location() );
		t << Qt::escape( s.location() ) << "<br />";
	}
	if( !s.role().isEmpty() )
	{
		st << "<br />" << Qt::escape( s.role() );
		t << Qt::escape( s.role() ) << "<br />";
	}
	if( !date.isNull() )
	{
		st << "<br />" << tr("Signed on") << " "
			<< DateTime( date ).formatDate( "dd. MMMM yyyy" ) << " "
			<< tr("time") << " "
			<< DateTime( date ).toString( "hh:mm" );
		t << tr("Signed on") << " "
			<< DateTime( date ).formatDate( "dd. MMMM yyyy" ) << " "
			<< tr("time") << " "
			<< DateTime( date ).toString( "hh:mm" );
	}
	setToolTip( tooltip );

	st << "<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\"><tr>";
	st << "<td>" << tr("Signature is") << " ";
	switch( s.validate() )
	{
	case DigiDocSignature::Valid: st << "<font color=\"green\">" << tr("valid"); break;
	case DigiDocSignature::Invalid: st << "<font color=\"red\">" << tr("not valid"); break;
	case DigiDocSignature::Unknown: st << "<font color=\"red\">" << tr("unknown"); break;
	}
	if( signature.isTest() )
		st << " (" << tr("Test signature") << ")";
	st << "</font>";
	st << "</td><td align=\"right\">";
	st << "<a href=\"details\">" << tr("Show details") << "</a>";
	st << "</td></tr><tr><td></td>";
	st << "<td align=\"right\">";
	st << "<a href=\"remove\">" << tr("Remove") << "</a>";
	st << "</td></tr></table>";

	setText( content );

	connect( this, SIGNAL(linkActivated(QString)), SLOT(link(QString)) );
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
	case DigiDocSignature::Invalid:
		status = tr("Signature is not valid");
		d->error->setText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		d->buttonBox->addButton( QDialogButtonBox::Help );
		break;
	case DigiDocSignature::Unknown:
		status = tr("Signature status unknown");
		d->error->setText( s.lastError().isEmpty() ? tr("Unknown error") : s.lastError() );
		d->buttonBox->addButton( QDialogButtonBox::Help );
		break;
	}
	if( d->error->text().isEmpty() )
		d->tabWidget->removeTab( 0 );
	d->title->setText( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + "\n" + status );
	setWindowTitle( c.toString( c.showCN() ? "CN serialNumber" : "GN SN serialNumber" ) + " - " + status );

	const QStringList l = s.locations();
	d->signerCity->setText( l.value( 0 ) );
	d->signerState->setText( l.value( 1 ) );
	d->signerZip->setText( l.value( 2 ) );
	d->signerCountry->setText( l.value( 3 ) );

	QStringList roles = s.roles();
	d->signerRole->setText( roles.value(0) );
	if( s.type() == DigiDocSignature::DDocType )
		delete d->signerResolution;
	else
		d->signerResolution->setText( roles.value(1) );

	// Certificate info
	QTreeWidget *t = d->signatureView;
	addItem( t, tr("Signing time"), DateTime( s.signTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
	addItem( t, tr("Signature method"), s.signatureMethod() );
	addItem( t, tr("Signature format"), s.mediaType() );
	addItem( t, tr("Signed file count"), QString::number( s.parent()->documentModel()->rowCount() ) );
	addItem( t, tr("Certificate serialnumber"), c.serialNumber() );
	addItem( t, tr("Certificate valid at"), DateTime( c.effectiveDate() ).toStringZ( "dd.MM.yyyy" ) );
	addItem( t, tr("Certificate valid until"), DateTime( c.expiryDate() ).toStringZ( "dd.MM.yyyy" ) );
	addItem( t, tr("Certificate issuer"), c.issuerInfo( QSslCertificate::CommonName ) );
	t->resizeColumnToContents( 0 );

	// OCSP info
	if( s.type() == DigiDocSignature::DDocType ||
		s.type() == DigiDocSignature::TMType )
	{
		SslCertificate ocsp = s.ocspCert();
		addItem( d->ocspView, tr("Certificate issuer"), ocsp.issuerInfo( QSslCertificate::CommonName ) );
		addItem( d->ocspView, tr("Certificate serialnumber"), ocsp.serialNumber() );
		addItem( d->ocspView, tr("Time"), DateTime( s.dateTime() ).toStringZ( "dd.MM.yyyy hh:mm:ss" ) );
		addItem( d->ocspView, tr("Hash value of validity confirmation"), SslCertificate::toHex( s.ocspDigestValue() ) );
		addItem( d->ocspView, tr("Nonce value"), SslCertificate::toHex( s.ocspNonce() ) );
		d->ocspView->resizeColumnToContents( 0 );
	}
	else
		d->tabWidget->removeTab( 3 );
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
