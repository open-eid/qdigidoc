/*
 * QEstEidCommon
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

#include "CertificateWidget.h"

#include "ui_CertificateWidget.h"
#include "SslCertificate.h"

#include <QDateTime>
#include <QDesktopServices>
#include <QFileDialog>
#include <QMessageBox>
#include <QTextStream>
#include <QSslKey>

class CertificateDialogPrivate: public Ui::CertificateDialog
{
public:
	QSslCertificate cert;
};

CertificateDialog::CertificateDialog( QWidget *parent )
:	QDialog( parent )
,	d( new CertificateDialogPrivate )
{
	d->setupUi( this );
	d->tabWidget->removeTab( 2 );
}

CertificateDialog::CertificateDialog( const QSslCertificate &cert, QWidget *parent )
:	QDialog( parent )
,	d( new CertificateDialogPrivate )
{
	d->setupUi( this );
	setCertificate( cert );
	d->tabWidget->removeTab( 2 );
}

CertificateDialog::~CertificateDialog() { delete d; }

void CertificateDialog::addItem( const QString &variable, const QString &value, const QVariant &valueext )
{
	QTreeWidgetItem *t = new QTreeWidgetItem( d->parameters );
	t->setText( 0, variable );
	t->setText( 1, value );
	t->setData( 1, Qt::UserRole, valueext );
	d->parameters->addTopLevelItem( t );
}

void CertificateDialog::on_parameters_itemSelectionChanged()
{
	if ( !d->parameters->selectionModel()->hasSelection() || !d->parameters->selectedItems().size() )
		return;
	if( !d->parameters->selectedItems().value(0)->data( 1, Qt::UserRole ).toString().isEmpty() )
		d->parameterContent->setPlainText( d->parameters->selectedItems().value(0)->data( 1, Qt::UserRole ).toString() );
	else
		d->parameterContent->setPlainText( d->parameters->selectedItems().value(0)->text( 1 ) );
}

void CertificateDialog::save()
{
	QString file = QFileDialog::getSaveFileName( this,
		tr("Save certificate"),
		QString( "%1%2%3.cer" )
			.arg( QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) )
			.arg( QDir::separator() )
			.arg( d->cert.subjectInfo( "serialNumber" ) ),
		tr("Certificates (*.cer *.crt *.pem)") );
	if( file.isEmpty() )
		return;

	QFile f( file );
	if( f.open( QIODevice::WriteOnly ) )
	{
		f.write( QFileInfo( file ).suffix().toLower() == "pem" ? d->cert.toPem() : d->cert.toDer() );
		f.close();
	}
	else
		QMessageBox::warning( this, tr("Save certificate"), tr("Failed to save file") );
}

void CertificateDialog::setCertificate( const QSslCertificate &cert )
{
	d->cert = cert;
	SslCertificate c = cert;
	QString i;
	QTextStream s( &i );
	s << "<b>" << tr("Certificate Information") << "</b><br />";
	s << "<hr>";
	s << "<b>" << tr("This certificate is intended for following purpose(s):") << "</b>";
	s << "<ul>";
	Q_FOREACH( const QString &ext, c.enhancedKeyUsage() )
		s << "<li>" << ext << "</li>";
	s << "</ul>";
	s << "<br /><br /><br /><br />";
	//s << tr("* Refer to the certification authority's statement for details.") << "<br />";
	s << "<hr>";
	s << "<p style='margin-left: 30px;'>";
	s << "<b>" << tr("Issued to:") << "</b> " << c.subjectInfo( QSslCertificate::CommonName );
	s << "<br /><br /><br />";
	s << "<b>" << tr("Issued by:") << "</b> " << c.issuerInfo( QSslCertificate::CommonName );
	s << "<br /><br /><br />";
	s << "<b>" << tr("Valid from") << "</b> " << c.effectiveDate().toLocalTime().toString( "dd.MM.yyyy" ) << " ";
	s << "<b>" << tr("to") << "</b> "<< c.expiryDate().toLocalTime().toString( "dd.MM.yyyy" );
	s << "</p>";
	d->info->setHtml( i );

	addItem( tr("Version"), "V" + c.version() );
	addItem( tr("Serial number"), QString( "%1 (0x%2)" )
		.arg( c.serialNumber().constData() )
		.arg( QString::number( c.serialNumber().toInt(), 16 ) ) );
	addItem( tr("Signature algorithm"), "sha1RSA" );

	QStringList text, textExt;
	QList<QByteArray> subjects;
	subjects << "CN" << "OU" << "O" << "C";
	Q_FOREACH( const QByteArray &subject, subjects )
	{
		const QString &data = c.issuerInfo( subject );
		if( data.isEmpty() )
			continue;
		text << data;
		textExt << QString( "%1 = %2" ).arg( subject.constData() ).arg( data );
	}
	addItem( tr("Issuer"), text.join( ", " ), textExt.join( "\n" ) );
	addItem( tr("Valid from"), c.effectiveDate().toLocalTime().toString( "dd.MM.yyyy hh:mm:ss" ) );
	addItem( tr("Vaild to"), c.expiryDate().toLocalTime().toString( "dd.MM.yyyy hh:mm:ss" ) );

	subjects.clear();
	text.clear();
	textExt.clear();
	subjects << "serialNumber" << "GN" << "SN" << "CN" << "OU" << "O" << "C";
	Q_FOREACH( const QByteArray &subject, subjects )
	{
		const QString &data = c.subjectInfo( subject );
		if( data.isEmpty() )
			continue;
		text << data;
		textExt << QString( "%1 = %2" ).arg( subject.constData() ).arg( data );
	}
	addItem( tr("Subject"), text.join( ", " ), textExt.join( "\n" ) );
	addItem( tr("Public key"), QString("%1 (%2)")
			.arg( c.publicKey().algorithm() == QSsl::Rsa ? "RSA" : "DSA" )
			.arg( c.publicKey().length() ),
		c.toHex( c.publicKey().toDer() ) );

	QStringList enhancedKeyUsage = c.enhancedKeyUsage();
	if( !enhancedKeyUsage.isEmpty() )
		addItem( tr("Enhanched key usage"), enhancedKeyUsage.join( ", " ), enhancedKeyUsage.join( "\n" ) );
	QStringList policies = c.policies();
	if( !policies.isEmpty() )
		addItem( tr("Certificate policies"), policies.join( ", " ) );
	addItem( tr("Authority key identifier"), c.toHex( c.authorityKeyIdentifier() ) );
	addItem( tr("Subject key identifier"), c.toHex( c.subjectKeyIdentifier() ) );
	QStringList keyUsage = c.keyUsage().values();
	if( !keyUsage.isEmpty() )
		addItem( tr("Key usage"), keyUsage.join( ", " ), keyUsage.join( "\n" ) );
}
