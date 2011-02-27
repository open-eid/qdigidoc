/*
 * QDigiDocCrypt
 *
 * Copyright (C) 2009,2010 Jargo Kõster <jargo@innovaatik.ee>
 * Copyright (C) 2009,2010 Raul Metsma <raul@innovaatik.ee>
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

#include <QDebug>

PrintSheet::PrintSheet( DigiDoc *doc, QPrinter *p )
:	QPainter( p )
{
	//begin( p );

	int margin	= 30;
	int left	= p->pageRect().x();
	int right	= p->pageRect().topRight().x() - 2*margin;
	int top		= p->pageRect().topLeft().y() + 30;

#ifdef Q_OS_MAC
	scale( 0.8, 0.8 );
	right /= 0.8;
#endif

	QFont text = font();
	text.setFamily( "Arial, Helvetica, sans-serif" );
	text.setPixelSize( 12 );

	QFont head = text;
	head.setPixelSize( 28 );

	QFont sHead = head;
	sHead.setPixelSize( 18 );

	QPen oPen = pen();

	QPen hPen = oPen;
	hPen.setWidth( 2 );

	QPen sPen = oPen;
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
	drawRect( left, top+5, right - margin, 20*doc->documentModel()->rowCount() );
	for( int i = 0; i < doc->documentModel()->rowCount(); ++i )
	{
		drawLine( left+395, top+5, left+395, top+25 );
		top += 20;
		drawText( left+5, top, doc->documentModel()->index( i, 0 ).data().toString() );
		drawText( left+400, top, doc->documentModel()->index( i, 2 ).data().toString() );
		drawLine( left, top+5, right, top+5 );
	}
	top += 35;

	setFont( sHead );
	drawText( left, top, tr("SIGNERS") );
	setPen( sPen );
	drawLine( left, top+3, right, top+3 );
	top += 30;
	
	setFont( text );
	setPen( oPen );

	int i = 1;
	Q_FOREACH( DigiDocSignature sig, doc->signatures() )
	{
		const SslCertificate cert = sig.cert();
		bool tempel = cert.isTempel();

		drawText( left, top, tr("NO.") );
		drawLine( left+35, top+5, left+35, top+25 );
		drawText( left+40, top, tempel ? tr( "COMPANY" ) : tr( "NAME" ) );
		drawLine( right-285, top+5, right-285, top+25 );
		drawText( right-280, top, tempel ? tr("REGISTER CODE") : tr("PERSONAL CODE") );
		drawLine( right-145, top+5, right-145, top+25 );
		drawText( right-140, top, tr("TIME") );
		drawRect( left, top+5, right - margin, 20 );
		top += 20;

		drawText( left+5, top, QString::number( i ) );
		drawText( left+40, top, cert.toString( tempel ? "CN" : "GN SN" ) );
		drawText( right-280, top, cert.subjectInfo( "serialNumber" ) );
		drawText( right-140, top, sig.dateTime().toString( "dd.MM.yyyy hh:mm:ss" ) );
		top += 25;

		drawText( left+3, top, tr("VALIDITY OF SIGNATURE") );
		drawRect( left, top+5, right - margin, 20 );
		QString valid = tr("SIGNATURE")+" ";
		switch( sig.validate() )
		{
			case DigiDocSignature::Valid: valid.append( tr("VALID") ); break;
			case DigiDocSignature::Invalid: valid.append( tr("NOT VALID") ); break;
			case DigiDocSignature::Unknown: valid.append( tr("UNKNOWN") ); break;
		}
		drawText( left+5, top+20, valid );
		top += 45;

		drawText( left+3, top, tr("ROLE / RESOLUTION") );
		drawRect( left, top+5, right - margin, 20 );
		drawText( left+5, top+20, sig.role() );
		top += 45;

		drawText( left+3, top, tr("PLACE OF CONFIRMATION (CITY, STATE, ZIP, COUNTRY)") );
		drawText( right-200, top, tr("SERIAL NUMBER OF CERTIFICATE") );
		drawRect( left, top+5, right - margin, 20 );
		drawLine( right-205, top+5, right-205, top+25 );
		drawText( left+5, top+20, sig.location() );
		drawText( right-200, top+20, cert.serialNumber() );
		top += 45;

		drawText( left+3, top, tr("ISSUER OF CERTIFICATE") );
		drawText( left+187, top, tr("HASH VALUE OF ISSUER'S PUBLIC KEY") );
		drawRect( left, top+5, right - margin, 20 );
		drawLine( left+180, top+5, left+180, top+25 );
		drawText( left+5, top+20, cert.issuerInfo( QSslCertificate::CommonName ) );
		drawText( left+187, top+20, cert.toHex( cert.authorityKeyIdentifier() ) );
		top += 45;

		drawText( left+3, top, tr("HASH VALUE OF VALIDITY CONFIRMATION (OCSP RESPONSE)") );
		drawRect( left, top+5, right - margin, 20 );
		drawText( left+5, top+20, cert.toHex( sig.digestValue() ) );
		top += 60;

		++i;
	}
	save();
	QTextDocument textDoc;
	textDoc.setTextWidth( right - margin );
	textDoc.setHtml( tr("The print out of files listed in the section <b>\"Signed Files\"</b> "
						"are inseparable part of this Validity Confirmation Sheet.") );
	translate( QPoint( left, top - 30) );
	textDoc.drawContents( this , QRectF( 0, 0, right - margin, 40) );
	top += 30;
	restore();

	drawText( left+3, top, tr("NOTES") );
	top += 10;
	drawRect( left, top, right - margin, 80 );

	end();
}
