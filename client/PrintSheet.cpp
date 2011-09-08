/*
 * QDigiDocCrypt
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

#include "PrintSheet.h"

#include <DigiDoc.h>
#include <common/SslCertificate.h>

#include <QDateTime>
#include <QPrinter>
#include <QTextDocument>

PrintSheet::PrintSheet( DigiDoc *doc, QPrinter *printer )
:	QPainter( printer )
,	p( printer )
{
	printer->setOrientation( QPrinter::Portrait );

	QDateTime utc = QDateTime::currentDateTimeUtc();
	utc.setTimeSpec( Qt::LocalTime );
	int diffsec = utc.secsTo( QDateTime::currentDateTime() );
	QString timediff = diffsec >= 0 ? "+" : "-";
	timediff += QTime().addSecs( diffsec >= 0 ? diffsec : -diffsec ).toString( "hh:mm" );

	left		= p->pageRect().x();
	margin		= left;
	right		= p->pageRect().topRight().x() - 2*margin;
	top			= p->pageRect().topLeft().y() + 30;

#ifdef Q_OS_MAC
	scale( 0.8, 0.8 );
	right /= 0.8;
#endif

	QFont text = font();
	text.setFamily( "Arial, Liberation Sans, Helvetica, sans-serif" );
	text.setPixelSize( 12 );

	QFont head = text;
	QFont sHead = text;
	head.setPixelSize( 28 );
	sHead.setPixelSize( 18 );

	QPen oPen = pen();
	QPen sPen = pen();
	QPen hPen = pen();
	hPen.setWidth( 2 );
	sPen.setWidth( 1 );
	sPen.setStyle( Qt::DotLine );

	setFont( head );
	drawText( left, top, tr("VALIDITY CONFIRMATION SHEET") );
	setPen( hPen );
	drawLine( left, top+3, right, top+3 );
	top += 45;

	setFont( sHead );
	drawText( left, top, tr("SIGNED FILES") );
	setPen( sPen );
	drawLine( left, top+3, right, top+3 );
	top += 30;

	setFont( text );
	setPen( oPen );
	drawText( left, top, tr("FILE NAME") );
	drawText( left+400, top, tr("FILE SIZE") );
	for( int i = 0; i < doc->documentModel()->rowCount(); ++i )
	{
		drawLine( left, top+5, right, top+5 );
		drawLine( left, top+5, left, top+25 );
		drawLine( left+395, top+5, left+395, top+25 );
		drawLine( right, top+5, right, top+25 );
		top += 20;
		drawText( left+5, top, doc->documentModel()->index( i, 0 ).data().toString() );
		drawText( left+400, top, doc->documentModel()->index( i, 2 ).data().toString() );
		drawLine( left, top+5, right, top+5 );
		newPage( 50 );
	}
	top += 35;

	newPage( 50 );
	setFont( sHead );
	drawText( left, top, tr("SIGNERS") );
	setPen( sPen );
	drawLine( left, top+3, right, top+3 );
	top += 30;
	
	setFont( text );
	setPen( oPen );

	int i = 1;
	Q_FOREACH( const DigiDocSignature &sig, doc->signatures() )
	{
		newPage( 50 );
		const SslCertificate cert = sig.cert();
		bool tempel = cert.isTempel();

		drawText( left, top, tr("NO.") );
		drawLine( left+35, top+5, left+35, top+25 );
		drawText( left+40, top, tempel ? tr( "COMPANY" ) : tr( "NAME" ) );
		drawLine( right-305, top+5, right-305, top+25 );
		drawText( right-300, top, tempel ? tr("REGISTER CODE") : tr("PERSONAL CODE") );
		drawLine( right-165, top+5, right-165, top+25 );
		drawText( right-160, top, tr("TIME") );
		drawRect( left, top+5, right - margin, 20 );
		top += 20;

		drawText( left+5, top, QString::number( i ) );
		drawText( left+40, top, cert.toString( cert.showCN() ? "CN" : "GN SN" ) );
		drawText( right-300, top, cert.subjectInfo( "serialNumber" ) );
		drawText( right-160, top, sig.dateTime().toString( "dd.MM.yyyy hh:mm:ss" ) + " " + timediff );
		top += 25;

		QString valid = tr("SIGNATURE") + " ";
		switch( sig.validate() )
		{
			case DigiDocSignature::Valid: valid.append( tr("VALID") ); break;
			case DigiDocSignature::Invalid: valid.append( tr("NOT VALID") ); break;
			case DigiDocSignature::Unknown: valid.append( tr("UNKNOWN") ); break;
		}
		if( sig.isTest() )
			valid += " " + tr("(NB! TEST SIGNATURE)");
		customText( tr("VALIDITY OF SIGNATURE"), valid );
		top += 45;

		customText( tr("ROLE / RESOLUTION"), sig.role() );
		top += 45;

		customText( tr("PLACE OF CONFIRMATION (CITY, STATE, ZIP, COUNTRY)"), sig.location() );
		top += 45;

		customText( tr("SERIAL NUMBER OF SIGNER CERTIFICATE"), cert.serialNumber() );
		top += 45;

		customText( tr("ISSUER OF CERTIFICATE"), cert.issuerInfo( QSslCertificate::CommonName ) );
		drawText( left+207, top, tr("HASH VALUE OF ISSUER'S PUBLIC KEY") );
		drawLine( left+200, top+5, left+200, top+25 );
		drawText( left+207, top+20, cert.toHex( cert.authorityKeyIdentifier() ) );
		top += 45;

		customText( tr("HASH VALUE OF VALIDITY CONFIRMATION (OCSP RESPONSE)"), cert.toHex( sig.ocspDigestValue() ) );
		top += 60;

		++i;
	}
	save();
	newPage( 50 );
	QTextDocument textDoc;
	textDoc.setTextWidth( right - margin );
	textDoc.setHtml( tr("The print out of files listed in the section <b>\"Signed Files\"</b> "
						"are inseparable part of this Validity Confirmation Sheet.") );
	translate( QPoint( left, top - 30) );
	textDoc.drawContents( this , QRectF( 0, 0, right - margin, 40) );
	top += 30;
	restore();

	newPage( 90 );
	drawText( left+3, top, tr("NOTES") );
	top += 10;
	drawRect( left, top, right - margin, 80 );

	end();
}

void PrintSheet::customText( const QString &title, const QString &text )
{
	newPage( 50 );
	drawText( left+3, top, title );
	drawRect( left, top+5, right - margin, 20 );
	drawText( left+5, top+20, text );
}

void PrintSheet::newPage( int height )
{
	if ( top + height > p->pageRect().height() )
	{
		p->newPage();
		top = p->pageRect().topLeft().y() + 30;
	}
}
