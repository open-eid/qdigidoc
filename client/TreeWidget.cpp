/*
 * QDigiDocClient
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

#include "TreeWidget.h"

#include "Application.h"
#include "DigiDoc.h"

#include <common/Common.h>

#include <QDesktopServices>
#include <QFileDialog>
#include <QHeaderView>
#include <QKeyEvent>
#include <QMessageBox>

TreeWidget::TreeWidget( QWidget *parent )
:	QTreeView( parent )
{}

void TreeWidget::clicked( const QModelIndex &index )
{
	switch( index.column() )
	{
	case 3:
	{
		QString dest;
		while( true )
		{
			dest = Common::normalized( QFileDialog::getSaveFileName( qApp->activeWindow(),
				tr("Save file"), QString( "%1/%2" )
					.arg( QDesktopServices::storageLocation( QDesktopServices::DocumentsLocation ) )
					.arg( m->index( index.row(), 0 ).data().toString() ) ) );
			if( !dest.isEmpty() && !Common::canWrite( dest ) )
			{
				QMessageBox::warning( qApp->activeWindow(), tr("DigiDoc3 client"),
					tr( "You dont have sufficient privilegs to write this file into folder %1" ).arg( dest ) );
			}
			else
				break;
		}
		QString src = m->index( index.row(), 0 ).data( Qt::UserRole ).toString();
		if( !dest.isEmpty() && !src.isEmpty() && dest != src )
			QFile::copy( src, dest );
		break;
	}
	case 4: m->removeRow( index.row() ); break;
	default: break;
	}
}

void TreeWidget::keyPressEvent( QKeyEvent *e )
{
	QModelIndexList i = selectionModel()->selectedRows();
	if( hasFocus() && !i.isEmpty() && i[0].isValid() )
	{
		switch( e->key() )
		{
		case Qt::Key_Delete:
			m->removeRow( i[0].row() );
			e->accept();
			break;
		case Qt::Key_Return:
			m->open( i[0] );
			e->accept();
			break;
		default: break;
		}
	}
	QTreeView::keyPressEvent( e );
}

void TreeWidget::setDocumentModel( DocumentModel *model )
{
	setModel( m = model );
	header()->setStretchLastSection( false );
	header()->setResizeMode( 0, QHeaderView::Stretch );
	header()->setResizeMode( 1, QHeaderView::ResizeToContents );
	header()->setResizeMode( 2, QHeaderView::ResizeToContents );
	header()->setResizeMode( 3, QHeaderView::ResizeToContents );
	header()->setResizeMode( 4, QHeaderView::ResizeToContents );
	connect( this, SIGNAL(clicked(QModelIndex)), SLOT(clicked(QModelIndex)) );
	connect( this, SIGNAL(doubleClicked(QModelIndex)), m, SLOT(open(QModelIndex)) );
}
