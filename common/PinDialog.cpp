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

#include "PinDialog.h"

#include "SslCertificate.h"

#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegExpValidator>
#include <QVBoxLayout>

PinDialog::PinDialog( QWidget *parent )
:	QDialog( parent )
{}

PinDialog::PinDialog( PinType type, const QSslCertificate &cert, QWidget *parent )
:	QDialog( parent )
{
	SslCertificate c = cert;
	init( type, c.toString( c.isTempel() ? "CN serialNumber" : "GN SN serialNumber" ) );
}

PinDialog::PinDialog( PinType type, const QString &title, QWidget *parent )
:	QDialog( parent )
{ init( type, title ); }

void PinDialog::init( PinType type, const QString &title )
{
	setWindowModality( Qt::ApplicationModal );
	setWindowTitle( title );

	QLabel *label = new QLabel( this );
	QVBoxLayout *l = new QVBoxLayout( this );
	l->addWidget( label );

	switch( type )
	{
	case Pin1Type:
		label->setText( QString( "<b>%1</b><br />%2<br />%3" )
			.arg( title )
			.arg( tr("Selected action requires auth certificate.") )
			.arg( tr("For using auth certificate enter PIN1") ) );
		regexp.setPattern( "\\d{4,12}" );
		break;
	case Pin2Type:
		label->setText( QString( "<b>%1</b><br />%2<br />%3" )
			.arg( title )
			.arg( tr("Selected action requires sign certificate.") )
			.arg( tr("For using sign certificate enter PIN2") ) );
		regexp.setPattern( "\\d{5,12}" );
		break;
	case Pin1PinpadType:
#if QT_VERSION >= 0x040500
		setWindowFlags( (windowFlags() | Qt::CustomizeWindowHint) & ~Qt::WindowCloseButtonHint );
#endif
		label->setText( QString( "<b>%1</b><br />%2<br />%3" )
			.arg( title )
			.arg( tr("Selected action requires auth certificate.") )
			.arg( tr("For using auth certificate enter PIN1 with pinpad") ) );
		return;
	case Pin2PinpadType:
#if QT_VERSION >= 0x040500
		setWindowFlags( (windowFlags() | Qt::CustomizeWindowHint) & ~Qt::WindowCloseButtonHint );
#endif
		label->setText( QString( "<b>%1</b><br />%2<br />%3" )
			.arg( title )
			.arg( tr("Selected action requires sign certificate.") )
			.arg( tr("For using sign certificate enter PIN2 with pinpad") ) );
		return;
	}

	m_text = new QLineEdit( this );
	m_text->setEchoMode( QLineEdit::Password );
	m_text->setFocus();
	m_text->setValidator( new QRegExpValidator( regexp, m_text ) );
	connect( m_text, SIGNAL(textEdited(QString)), SLOT(textEdited(QString)) );
	l->addWidget( m_text );

	QDialogButtonBox *buttons = new QDialogButtonBox(
		QDialogButtonBox::Ok|QDialogButtonBox::Cancel, Qt::Horizontal, this );
	ok = buttons->button( QDialogButtonBox::Ok );
	ok->setAutoDefault( true );
	connect( buttons, SIGNAL(accepted()), SLOT(accept()) );
	connect( buttons, SIGNAL(rejected()), SLOT(reject()) );
	l->addWidget( buttons );

	textEdited( QString() );
}

QString PinDialog::text() const { return m_text->text(); }

void PinDialog::textEdited( const QString &text )
{ ok->setEnabled( regexp.exactMatch( text ) ); }
